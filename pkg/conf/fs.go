package conf

type FilesystemConfig struct {
	Mountpoint string `json:"mountpoint" yaml:"mountpoint"`
	Debug      bool   `json:"debug" yaml:"debug"`

	Spec []struct {
		PM     PasswordManagerConfig `json:"pm" yaml:"pm"`
		Mounts []MountConfig         `json:"mounts" yaml:"mounts"`
	} `json:"spec" yaml:"spec"`
}

type MountConfig struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
}
