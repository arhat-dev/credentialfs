package fs

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/term"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/pm"
)

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
		_, _ = fmt.Fprintf(os.Stdout, "Trying to login to %q\n", b.pm.ConfigName())

		err := b.pm.Login(func() (username, password string, err error) {
			_, _ = fmt.Fprintf(os.Stdout, "Please enter your username for pm %q: ", b.pm.ConfigName())
			_, err = fmt.Fscanf(os.Stdin, "%s\n", &username)
			if err != nil {
				println(err.Error())
			}

			_, _ = fmt.Fprintf(os.Stdout, "Please enter your password for pm %q: ", b.pm.ConfigName())
			pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				println(err.Error())
			}

			_, _ = fmt.Fprintf(os.Stdout, "\n")

			password = string(pwd)

			return
		})
		if err != nil {
			return err
		}

		for _, mount := range b.mounts {
			data, err := b.pm.Get(mount.From)
			if err != nil {
				return fmt.Errorf("failed to download %q from %q: %w", mount.From, b.pm.ConfigName(), err)
			}

			// TODO: make inode and files
			_ = data
		}

		_, _ = fmt.Fprintf(os.Stdout, "pm %q Login ok\n", b.pm.ConfigName())
	}

	return nil
}
