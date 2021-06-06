package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	bw "arhat.dev/bitwardenapi/bwinternal"
	"github.com/denisbrodbeck/machineid"

	"arhat.dev/credentialfs/pkg/pm"
	"arhat.dev/credentialfs/pkg/security"
)

// nolint:revive
const (
	Name = "bitwarden"

	officialServiceEndpointURL       = "https://vault.bitwarden.com"
	officialNotificationEndpointHost = "notifications.bitwarden.com"
)

func init() {
	pm.Register(
		Name,
		func(
			ctx context.Context,
			configName string,
			config interface{},
			keychainHandler security.KeychainHandler,
		) (pm.Interface, error) {
			c, ok := config.(*Config)
			if !ok {
				return nil, fmt.Errorf("unexpected non bitwarden config: %T", config)
			}

			pathPrefix := ""
			endpointURL := strings.TrimRight(c.EndpointURL, "/")
			if len(endpointURL) != 0 {
				u, err := url.Parse(endpointURL)
				if err != nil {
					return nil, fmt.Errorf("invalid endpoint url: %w", err)
				}

				pathPrefix = u.Path
			} else {
				endpointURL = officialServiceEndpointURL
			}

			deviceID := c.DeviceID
			if len(deviceID) == 0 {
				var err error
				deviceID, err = machineid.ID()
				if err != nil {
					return nil, fmt.Errorf("couldn't determine a stable device id, please provide your own")
				}
			}

			driver := &Driver{
				ctx:    ctx,
				client: nil,

				deviceID:           deviceID,
				endpointURL:        endpointURL,
				endpointPathPrefix: pathPrefix,

				configName:    configName,
				saveLogin:     c.SaveLogin,
				twoFactorKind: pm.TwoFactorKind(strings.ToLower(c.TwoFactorMethod)),

				cache:         newCipherCache(),
				subscriptions: newSubManager(),

				updateCh: make(chan pm.CredentialUpdate, 1),

				keychainHandler: keychainHandler,

				mu: &sync.RWMutex{},
			}

			client, err := bw.NewClient(
				endpointURL,
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
	DeviceID        string `json:"deviceID" yaml:"deviceID"`
	TwoFactorMethod string `json:"twoFactorMethod" yaml:"twoFactorMethod"`
}

var _ pm.Interface = (*Driver)(nil)

type Driver struct {
	ctx context.Context

	client *bw.Client

	deviceID           string
	endpointURL        string
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

	keychainHandler security.KeychainHandler

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

		savedBefore  = false
		loginUpdated = true
	)

	if !d.saveLogin {
		loginUpdated = false

		_ = d.keychainHandler.DeleteLogin(Name, d.configName)

		input, err = requestUserLogin(d.twoFactorKind, input)
		if err != nil {
			return err
		}
	} else {
		input = &pm.LoginInput{}

		// login may be saved before
		input.Username, input.Password, err = d.keychainHandler.GetLogin(Name, d.configName)
		if err != nil {
			switch {
			case errors.Is(err, security.ErrNotFound):
				input, err = requestUserLogin(d.twoFactorKind, input)
				if err != nil {
					return err
				}

				loginUpdated = true
			case errors.Is(err, security.ErrOldInvalid):
				_ = d.keychainHandler.DeleteLogin(Name, d.configName)

				input, err = requestUserLogin(d.twoFactorKind, input)
				if err != nil {
					return err
				}

				loginUpdated = true
			default:
				// unable to lookup keychain
				return err
			}
		} else {
			savedBefore = true
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
	if err == nil {
		if d.saveLogin && loginUpdated &&
			(len(input.Username) != 0 || len(input.Password) != 0) {

			err = d.keychainHandler.SaveLogin(Name, d.configName, input.Username, input.Password)
			if err != nil {
				return err
			}
		}
	}

	// first login try failed
	if !savedBefore {
		// user entered this login
		return err
	}

	// we were using saved login, request new login from user input
	_ = d.keychainHandler.DeleteLogin(Name, d.configName)
	input, err = requestUserLogin(d.twoFactorKind, input)
	if err != nil {
		return err
	}

	err = d.login(input)
	if err != nil {
		return err
	}

	if !d.saveLogin {
		return nil
	}

	err = d.keychainHandler.SaveLogin(Name, d.configName, input.Username, input.Password)
	if err != nil {
		return err
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
