package conf

import (
	"time"

	"github.com/spf13/pflag"
)

type FilesystemConfig struct {
	Mountpoint string `json:"mountpoint" yaml:"mountpoint"`
	Debug      bool   `json:"debug" yaml:"debug"`

	DefaultPermitDuration  time.Duration `json:"defaultPermitDuration" yaml:"defaultPermitDuration"`
	DefaultPenaltyDuration time.Duration `json:"defaultPenaltyDuration" yaml:"defaultPenaltyDuration"`

	LoginInterface string `json:"loginInterface" yaml:"loginInterface"`

	Spec []struct {
		PM     PasswordManagerConfig `json:"pm" yaml:"pm"`
		Mounts []MountConfig         `json:"mounts" yaml:"mounts"`
	} `json:"spec" yaml:"spec"`
}

type MountConfig struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`

	PenaltyDuration *time.Duration `json:"penaltyDuration" yaml:"penaltyDuration"`
	PermitDuration  *time.Duration `json:"permitDuration" yaml:"permitDuration"`
}

func FlagsForFilesystemConfig(prefix string, config *FilesystemConfig) *pflag.FlagSet {
	fs := pflag.NewFlagSet("fs", pflag.ExitOnError)
	fs.DurationVar(&config.DefaultPermitDuration, prefix+"defaultPermitDuration", 0, "")
	fs.DurationVar(&config.DefaultPenaltyDuration, prefix+"defaultPenaltyDuration", 10*time.Second, "")
	fs.StringVar(&config.LoginInterface, prefix+"loginInterface", "cli", "")
	return fs
}
