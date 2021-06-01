package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"arhat.dev/bitwardenapi/bwinternal"
	bw "arhat.dev/bitwardenapi/bwinternal"
	"arhat.dev/credentialfs/pkg/auth"
	"arhat.dev/credentialfs/pkg/pm"
)

// nolint:revive
const (
	Name = "bitwarden"
)

func init() {
	_ = bw.Client{}

	pm.Register(
		Name,
		func(ctx context.Context, configName string, config interface{}) (pm.Interface, error) {
			c, ok := config.(*Config)
			if !ok {
				return nil, fmt.Errorf("unexpected non bitwarden config: %T", config)
			}

			client, err := bwinternal.NewClient(
				c.EndpointURL,
				bw.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
					req.Header.Set("Device-Type", getDeviceType())
					req.Header.Set("Accept", "application/json")
					return nil
				}),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to create bitwarden client: %w", err)
			}

			return &Driver{
				ctx:        ctx,
				client:     client,
				configName: configName,
				saveLogin:  c.SaveLogin,

				mu: &sync.Mutex{},
			}, nil
		},
		func() interface{} {
			return &Config{}
		},
	)
}

type Config struct {
	EndpointURL string `json:"endpointURL" yaml:"endpointURL"`
	SaveLogin   bool   `json:"saveLogin" yaml:"saveLogin"`
}

var _ pm.Interface = (*Driver)(nil)

type Driver struct {
	ctx    context.Context
	client *bwinternal.Client

	configName string
	saveLogin  bool

	accessToken    string
	refreshToken   string
	preLoginKey    []byte
	hashedPassword string
	encKey         []byte
	encPrivateKey  []byte

	mu *sync.Mutex
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

func (d *Driver) Login(showLoginPrompt pm.LoginInputCallbackFunc) error {
	var (
		username string
		password string

		err error

		loginUpdated = true
	)

	if !d.saveLogin {
		loginUpdated = false

		_ = auth.DeleteLogin(Name, d.configName)

		username, password, err = showLoginPrompt()
		if err != nil {
			return err
		}
	} else {
		// login may be saved before
		username, password, err = auth.GetLogin(Name, d.configName)
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
			username, password, err = showLoginPrompt()
			if err != nil {
				return err
			}
		}
	}

	err = d.login(password, username)
	if err != nil {
		loginUpdated = true

		// wrong password, need user input
		username, password, err = showLoginPrompt()
		if err != nil {
			return err
		}

		err = d.login(password, username)
		if err != nil {
			return err
		}
	}

	if d.saveLogin && loginUpdated {
		err = auth.SaveLogin(Name, d.configName, username, password)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) Get(key string) ([]byte, error)       { return nil, fmt.Errorf("unimplemented") }
func (d *Driver) Update(key string, data []byte) error { return fmt.Errorf("unimplemented") }
