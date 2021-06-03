package fs

import (
	"context"
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/pm"
)

type bundle struct {
	pm     pm.Interface
	mounts []conf.MountConfig
}

type Manager struct {
	ctx context.Context

	debugFilesystem bool
	fsMountpoint    string

	fsSpec []*bundle

	fs Filesystem

	mu *sync.Mutex
}

func NewManager(ctx context.Context, config conf.FilesystemConfig) (*Manager, error) {
	mgr := &Manager{
		ctx:             ctx,
		debugFilesystem: config.Debug,
		fsMountpoint:    config.Mountpoint,

		mu: &sync.Mutex{},
	}

	for _, fsc := range config.Spec {
		pmd, err := pm.NewDriver(ctx, fsc.PM.Driver, fsc.PM.Name, fsc.PM.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create password manager %q: %w", fsc.PM.Name, err)
		}

		mgr.fsSpec = append(mgr.fsSpec, &bundle{
			pm:     pmd,
			mounts: fsc.Mounts,
		})
	}

	return mgr, nil
}

func (m *Manager) Start() (err error) {
	m.mu.Lock()
	defer func() {
		m.mu.Unlock()

		if err != nil {
			m.Stop()
		}
	}()

	m.fs, err = CreateFilesystem(m.fsMountpoint, m.debugFilesystem)
	if err != nil {
		return fmt.Errorf("failed to create fuse filesystem: %w", err)
	}

	err = m.fs.Start()
	if err != nil {
		return fmt.Errorf("failed to start fuse filesystem: %w", err)
	}

	for _, b := range m.fsSpec {
		_, _ = fmt.Fprintf(os.Stdout, "Trying to login to %q\n", b.pm.ConfigName())

		err = b.pm.Login(func() (username, password string, _ error) {
			_, _ = fmt.Fprintf(os.Stdout, "Please enter your username for pm %q: ", b.pm.ConfigName())
			_, err2 := fmt.Fscanf(os.Stdin, "%s\n", &username)
			if err2 != nil {
				println(err2.Error())
			}

			_, _ = fmt.Fprintf(os.Stdout, "Please enter your password for pm %q: ", b.pm.ConfigName())
			pwd, err2 := term.ReadPassword(int(os.Stdin.Fd()))
			if err2 != nil {
				println(err2.Error())
			}

			_, _ = fmt.Fprintf(os.Stdout, "\n")

			password = string(pwd)
			return
		})
		if err != nil {
			return err
		}

		for _, mount := range b.mounts {
			var data []byte
			data, err = b.pm.Get(mount.From)
			if err != nil {
				return fmt.Errorf("failed to download %q from %q: %w", mount.From, b.pm.ConfigName(), err)
			}

			if err != nil {
				return fmt.Errorf("failed to mount %q to %q: %w", mount.From, mount.To, err)
			}

			err = m.fs.BindData(m.ctx, mount.To, data)
			if err != nil {
				return fmt.Errorf("failed to bind data to filesystem: %w", err)
			}
		}

		_, _ = fmt.Fprintf(os.Stdout, "pm %q Login ok\n", b.pm.ConfigName())
	}

	return nil
}

func (m *Manager) Stop() (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fs == nil {
		return nil
	}

	return m.fs.Stop()
}
