package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/auth"
	"arhat.dev/credentialfs/pkg/pm"
)

// nolint:revive
const (
	Name = "bitwarden"
)

func init() {
	pm.Register(
		Name,
		func(ctx context.Context, configName string, config interface{}) (pm.Interface, error) {
			c, ok := config.(*Config)
			if !ok {
				return nil, fmt.Errorf("unexpected non bitwarden config: %T", config)
			}

			u, err := url.Parse(c.EndpointURL)
			if err != nil {
				return nil, fmt.Errorf("invalid endpoint url: %w", err)
			}

			driver := &Driver{
				ctx:                ctx,
				client:             nil,
				endpointPathPrefix: u.Path,

				configName:    configName,
				saveLogin:     c.SaveLogin,
				twoFactorKind: pm.TwoFactorKind(strings.ToLower(c.TwoFactorMethod)),

				cache:         newCipherCache(),
				subscriptions: newSubManager(),

				updateCh: make(chan pm.CredentialUpdate, 1),

				mu: &sync.RWMutex{},
			}
			client, err := bw.NewClient(
				c.EndpointURL,
				bw.WithRequestEditorFn(driver.fixRequest),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create bitwarden client: %w", err)
			}

			driver.client = client

			return driver, nil
		},
		func() interface{} {
			return &Config{}
		},
	)
}

type Config struct {
	EndpointURL     string `json:"endpointURL" yaml:"endpointURL"`
	SaveLogin       bool   `json:"saveLogin" yaml:"saveLogin"`
	TwoFactorMethod string `json:"twoFactorMethod" yaml:"twoFactorMethod"`
}

var _ pm.Interface = (*Driver)(nil)

type Driver struct {
	ctx context.Context

	client             *bw.Client
	endpointPathPrefix string

	// config options
	configName    string
	saveLogin     bool
	twoFactorKind pm.TwoFactorKind

	// jwt token
	accessToken string

	// user derived from access token
	user *bitwardenUser

	refreshToken   string
	masterKey      []byte
	hashedPassword string
	encKey         *bitwardenKey
	privateKey     *bitwardenKey

	cache         *cipherCache
	subscriptions *subManager

	updateCh chan pm.CredentialUpdate

	mu *sync.RWMutex
}

func (d *Driver) DriverName() string {
	return Name
}

func (d *Driver) ConfigName() string {
	return d.configName
}

func (d *Driver) Login(requestUserLogin pm.LoginInputCallbackFunc) error {
	var (
		input *pm.LoginInput

		err error

		loginUpdated = true
	)

	if !d.saveLogin {
		loginUpdated = false

		_ = auth.DeleteLogin(Name, d.configName)

		input, err = requestUserLogin(d.twoFactorKind, input)
		if err != nil {
			return err
		}
	} else {
		input = &pm.LoginInput{}

		// login may be saved before
		input.Username, input.Password, err = auth.GetLogin(Name, d.configName)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrNotFound):
			case errors.Is(err, auth.ErrOldInvalid):
				_ = auth.DeleteLogin(Name, d.configName)
			default:
				// unable to lookup keychain
				return err
			}

			loginUpdated = true
			input, err = requestUserLogin(d.twoFactorKind, input)
			if err != nil {
				return err
			}
		}

		if d.twoFactorKind != pm.TwoFactorKindNone {
			// we only haver username and password stored in system keychain
			// 2FA requires extra codes
			input, err = requestUserLogin(d.twoFactorKind, input)
			if err != nil {
				return err
			}
		}
	}

	err = d.login(input)
	if err != nil {
		return err
	}

	if d.saveLogin && loginUpdated &&
		(len(input.Username) != 0 || len(input.Password) != 0) {

		err = auth.SaveLogin(Name, d.configName, input.Username, input.Password)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) Sync(ctx context.Context) (<-chan pm.CredentialUpdate, error) {
	d.mu.RLock()
	encKey := d.encKey
	d.mu.RUnlock()

	err := d.buildCache(encKey)
	if err != nil {
		return nil, err
	}

	err = d.startSyncing(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to keep syncing with server: %w", err)
	}

	return d.updateCh, nil
}

func (d *Driver) Subscribe(subID string) ([]byte, error) {
	k := getCacheKey(subID)
	if k == nil {
		return nil, fmt.Errorf("invalid key %q", subID)
	}

	cipher := d.cache.Get(k.ItemName, k.ItemKey)
	if cipher == nil {
		return nil, fmt.Errorf("credential %q not found", subID)
	}

	if len(cipher.URL) == 0 {
		// not an attachment, return value directly
		d.subscriptions.Add(subID, cipher.CipherID)

		return cipher.Value, nil
	}

	// is an attachment url, download it

	data, err := d.downloadAttachment(cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to download attachment %q: %w", subID, err)
	}

	d.subscriptions.Add(subID, cipher.CipherID)

	return data, nil
}

// Flush previously built in memory cache
func (d *Driver) Flush() {
	d.cache.Clear(func(k cacheKey, v *cacheValue) bool {
		// do not clear cache if subscribed
		return !d.subscriptions.Check(v.CipherID, k.ItemName+"/"+k.ItemKey)
	})
}

func (d *Driver) Update(key string, data []byte) error {
	return fmt.Errorf("unimplemented")
}
