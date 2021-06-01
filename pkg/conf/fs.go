package conf

type FilesystemConfig []struct {
	PM PasswordManagerConfig `json:"pm" yaml:"pm"`

	Mounts []MountConfig `json:"mounts" yaml:"mounts"`
}

type MountConfig struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`
}
