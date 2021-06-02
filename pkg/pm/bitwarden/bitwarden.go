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
	_ = bw.Client{}

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

				attachments: &sync.Map{},

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
	EndpointURL string `json:"endpointURL" yaml:"endpointURL"`
	SaveLogin   bool   `json:"saveLogin" yaml:"saveLogin"`
}

var _ pm.Interface = (*Driver)(nil)

type attachmentKey struct {
	// decrypt(Item Name)
	ItemName string

	// decrypt(Attachments FileName)
	Filename string
}

type attachmentValue struct {
	// plaintext
	URL string

	// decrypted attachment key or org key
	Key *symmetricKey
}

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
	preLoginKey    []byte
	hashedPassword string
	encKey         *symmetricKey
	encPrivateKey  []byte

	// key: attachmentKey
	// value: url to get the attachment
	attachments *sync.Map

	mu *sync.RWMutex
}

func (d *Driver) fixRequest(ctx context.Context, req *http.Request) error {
	req.Header.Set("Device-Type", getDeviceType())
	req.Header.Set("Accept", "application/json")

	d.mu.RLock()
	if len(d.accessToken) != 0 {
		req.Header.Set("Authorization", "Bearer "+d.accessToken)
	}
	d.mu.RUnlock()

	return nil
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

	d.mu.RLock()
	encKey := d.encKey
	d.mu.RUnlock()

	return d.sync(encKey)
}

func (d *Driver) Get(key string) ([]byte, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid key %q", key)
	}

	specVal, ok := d.attachments.Load(attachmentKey{
		ItemName: parts[0],
		Filename: parts[1],
	})
	if !ok {
		return nil, fmt.Errorf("credential %q not found", key)
	}

	spec := specVal.(*attachmentValue)
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, spec.URL, nil)
	if err != nil {
		return nil, err
	}

	_ = d.fixRequest(d.ctx, req)

	resp, err := d.client.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request %q: %w", key, err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read attachment data: %w", err)
	}

	// TODO: decrypt data with key

	// data, err = decryptData(data, spec.Key)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to decrypt attachment content: %w", err)
	// }

	return data, nil
}

func (d *Driver) Update(key string, data []byte) error {
	return fmt.Errorf("unimplemented")
}
