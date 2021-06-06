package conf

import (
	"time"

	"github.com/spf13/pflag"
)

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

func FlagsForFilesystemConfig(prefix string, config *FilesystemConfig) *pflag.FlagSet {
	fs := pflag.NewFlagSet("fs", pflag.ExitOnError)
	fs.StringVar(&config.LoginInterface, prefix+"loginInterface", "cli", "")
	return fs
}
