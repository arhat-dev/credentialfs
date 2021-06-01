package bitwarden

import (
	"fmt"

	"arhat.dev/bitwardenapi/bwinternal"
	bw "arhat.dev/bitwardenapi/bwinternal"
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
		func(config interface{}) (pm.Interface, error) {
			c, ok := config.(*Config)
			if !ok {
				return nil, fmt.Errorf("unexpected non bitwarden config: %T", config)
			}

			client, err := bwinternal.NewClient(c.EndpointURL)
			if err != nil {
				return nil, fmt.Errorf("failed to create bitwarden client: %w", err)
			}

			return &Driver{
				client: client,
			}, nil
		},
		func() interface{} {
			return &Config{}
		},
	)
}

type Config struct {
	EndpointURL string `json:"endpointURL" yaml:"endpointURL"`
	SaveLogin   string `json:"saveLogin" yaml:"saveLogin"`
}

var _ pm.Interface = (*Driver)(nil)

type Driver struct {
	client bwinternal.ClientInterface
}

func (d *Driver) Login(password string) error          { return fmt.Errorf("unimplemented") }
func (d *Driver) Get(key string) ([]byte, error)       { return nil, fmt.Errorf("unimplemented") }
func (d *Driver) Update(key string, data []byte) error { return fmt.Errorf("unimplemented") }
