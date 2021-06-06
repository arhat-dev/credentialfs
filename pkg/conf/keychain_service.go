package conf

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"arhat.dev/credentialfs/pkg/security"
)

type KeychainServiceConfig struct {
	Name   string      `json:"name" yaml:"name"`
	Config interface{} `json:"config" yaml:"config"`
}

func (c *KeychainServiceConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	c.Name, c.Config, err = unmarshalKeychainServiceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func (c *KeychainServiceConfig) UnmarshalYAML(value *yaml.Node) error {
	m := make(map[string]interface{})

	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, m)
	if err != nil {
		return err
	}

	c.Name, c.Config, err = unmarshalKeychainServiceConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func unmarshalKeychainServiceConfig(m map[string]interface{}) (name string, config interface{}, err error) {
	n, ok := m["name"]
	if !ok {
		return
	}

	name, ok = n.(string)
	if !ok {
		err = fmt.Errorf("keychain service name must be a string")
		return
	}

	config, err = security.NewKeychainHandlerConfig(name)
	if err != nil {
		return
	}

	configRaw, ok := m["config"]
	if !ok {
		return
	}

	var configData []byte
	switch d := configRaw.(type) {
	case []byte:
		configData = d
	case string:
		configData = []byte(d)
	default:
		configData, err = yaml.Marshal(d)
		if err != nil {
			err = fmt.Errorf("failed to get pm config bytes: %w", err)
			return
		}
	}

	dec := yaml.NewDecoder(bytes.NewReader(configData))
	dec.KnownFields(true)
	err = dec.Decode(config)
	return
}
