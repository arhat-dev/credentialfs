package fs

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/pm"
	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/term"
)

func init() {
	_ = fs.Inode{}
}

type bundle struct {
	pm     pm.Interface
	mounts []conf.MountConfig
}

type Manager struct {
	fs []*bundle
}

func NewManager(ctx context.Context, config conf.FilesystemConfig) (*Manager, error) {
	mgr := &Manager{}
	for _, fsc := range config {
		pmd, err := pm.NewDriver(ctx, fsc.PM.Driver, fsc.PM.Name, fsc.PM.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create password manager %q: %w", fsc.PM.Name, err)
		}

		mgr.fs = append(mgr.fs, &bundle{
			pm:     pmd,
			mounts: fsc.Mounts,
		})
	}

	return mgr, nil
}

func (m *Manager) Start() error {
	for _, b := range m.fs {
		_, _ = fmt.Fprintf(os.Stdout, "Trying to login to %q", b.pm.ConfigName())

		err := b.pm.Login(func() (username, password string, err error) {
			_, _ = fmt.Fprintf(os.Stdout, "Please enter your username for pm %q: ", b.pm.ConfigName())
			_, err = fmt.Fscanf(os.Stdin, "%s\n", &username)
			if err != nil {
				println(err.Error())
			}

			_, _ = fmt.Fprintf(os.Stdout, "Please enter your password for pm %q: ", b.pm.ConfigName())
			pwd, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				println(err.Error())
			}

			password = string(pwd)

			return
		})
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintf(os.Stdout, "pm %q Login ok\n", b.pm.ConfigName())
	}

	return nil
}
