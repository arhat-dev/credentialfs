package conf

import "time"

type FilesystemConfig struct {
	Mountpoint string `json:"mountpoint" yaml:"mountpoint"`
	Debug      bool   `json:"debug" yaml:"debug"`

	LoginInterface string `json:"loginInterface" yaml:"loginInterface"`

	Spec []struct {
		PM     PasswordManagerConfig `json:"pm" yaml:"pm"`
		Mounts []MountConfig         `json:"mounts" yaml:"mounts"`
	} `json:"spec" yaml:"spec"`
}

type MountConfig struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`

	PermitDuration time.Duration `json:"permitDuration" yaml:"permitDuration"`
}
