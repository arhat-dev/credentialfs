package conf

import (
	"time"

	"github.com/spf13/pflag"
)

type FilesystemConfig struct {
	Mountpoint string `json:"mountpoint" yaml:"mountpoint"`
	Debug      bool   `json:"debug" yaml:"debug"`

	DefaultPermitDuration  time.Duration `json:"default_permit_duration" yaml:"default_permit_duration"`
	DefaultPenaltyDuration time.Duration `json:"default_penalty_duration" yaml:"default_penalty_duration"`

	LoginInterface string `json:"login_interface" yaml:"login_interface"`

	Spec []struct {
		PM     PasswordManagerConfig `json:"pm" yaml:"pm"`
		Mounts []MountConfig         `json:"mounts" yaml:"mounts"`
	} `json:"spec" yaml:"spec"`
}

type MountConfig struct {
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`

	PenaltyDuration *time.Duration `json:"penalty_duration" yaml:"penalty_duration"`
	PermitDuration  *time.Duration `json:"permit_duration" yaml:"permit_duration"`
}

func FlagsForFilesystemConfig(prefix string, config *FilesystemConfig) *pflag.FlagSet {
	fs := pflag.NewFlagSet("fs", pflag.ExitOnError)
	fs.DurationVar(&config.DefaultPermitDuration, prefix+"default-permit-duration", 0, "")
	fs.DurationVar(&config.DefaultPenaltyDuration, prefix+"default-penalty-duration", 10*time.Second, "")
	fs.StringVar(&config.LoginInterface, prefix+"login-interface", "cli", "")
	return fs
}
