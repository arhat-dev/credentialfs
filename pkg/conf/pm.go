package conf

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"arhat.dev/credentialfs/pkg/pm"
)

type PasswordManagerConfig struct {
	Driver string `json:"driver" yaml:"driver"`

	Name   string      `json:"name" yaml:"name"`
	Config interface{} `json:"config" yaml:"config"`
}

func (c *PasswordManagerConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	c.Driver, c.Name, c.Config, err = unmarshalPasswordManagerConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func (c *PasswordManagerConfig) UnmarshalYAML(value *yaml.Node) error {
	m := make(map[string]interface{})

	data, err := yaml.Marshal(value)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, m)
	if err != nil {
		return err
	}

	c.Driver, c.Name, c.Config, err = unmarshalPasswordManagerConfig(m)
	if err != nil {
		return err
	}

	return nil
}

func unmarshalPasswordManagerConfig(m map[string]interface{}) (driver, name string, config interface{}, err error) {
	n, ok := m["driver"]
	if !ok {
		return
	}

	driver, ok = n.(string)
	if !ok {
		err = fmt.Errorf("pm driver name must be a string")
		return
	}

	config, err = pm.NewConfig(driver)
	if err != nil {
		return
	}

	n, ok = m["name"]
	if !ok {
		return
	}

	name, ok = n.(string)
	if !ok {
		err = fmt.Errorf("pm name must be a string")
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
