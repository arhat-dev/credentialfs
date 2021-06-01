package conf

type PasswordManagerConfig struct {
	Driver string `json:"driver" yaml:"driver"`

	Name   string      `json:"name" yaml:"name"`
	Config interface{} `json:"config" yaml:"config"`
}
