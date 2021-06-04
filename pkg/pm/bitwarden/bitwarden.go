package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
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

				configName: configName,
				saveLogin:  c.SaveLogin,

				cache: newCipherCache(),

				twoFactorKind: pm.TwoFactorKind(strings.ToLower(c.TwoFactorMethod)),

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

	configName string
	saveLogin  bool

	// jwt token
	accessToken string

	// user derived from access token
	user *bitwardenUser

	refreshToken   string
	masterKey      []byte
	hashedPassword string
	encKey         *bitwardenKey
	privateKey     *bitwardenKey

	cache *cipherCache

	twoFactorKind pm.TwoFactorKind

	mu *sync.RWMutex
}

func (d *Driver) DriverName() string {
	return Name
}

func (d *Driver) ConfigName() string {
	return d.configName
}

func (d *Driver) update(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	f()
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

func (d *Driver) Sync(stop <-chan struct{}) (<-chan pm.CredentialUpdate, error) {
	d.mu.RLock()
	encKey := d.encKey
	d.mu.RUnlock()

	err := d.buildCache(encKey)
	if err != nil {
		return nil, err
	}

	// TODO: implement continuous sync

	return nil, nil
}

func (d *Driver) Subscribe(key string) ([]byte, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid key %q", key)
	}

	cipher := d.cache.Get(parts[0], parts[1])
	if cipher == nil {
		return nil, fmt.Errorf("credential %q not found", key)
	}

	if len(cipher.URL) == 0 {
		// not an attachment, return value directly
		// TODO: add this key to subscription
		return cipher.Value, nil
	}

	// is an attachment url, key must present

	if cipher.Key == nil {
		return nil, fmt.Errorf("invalid cipher cache: key not found")
	}

	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, cipher.URL, nil)
	if err != nil {
		return nil, err
	}

	err = d.fixRequest(d.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fix attachment request: %w", err)
	}

	resp, err := d.client.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request attachment %q: %w", key, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read attachment data: %w", err)
	}

	data, err = decryptData(data, cipher.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attachment content: %w", err)
	}

	// TODO: add this key to subscription

	return data, nil
}

// Flush previously built in memory cache
func (d *Driver) Flush() {
	d.cache.Clear()
}

func (d *Driver) Update(key string, data []byte) error {
	return fmt.Errorf("unimplemented")
}
