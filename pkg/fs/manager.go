package fs

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/constant"
	"arhat.dev/credentialfs/pkg/pm"
	"arhat.dev/credentialfs/pkg/ui"
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

	createLoginHandleFunc func(configName string) pm.LoginInputCallbackFunc

	mu *sync.Mutex
}

func NewManager(ctx context.Context, config conf.FilesystemConfig) (*Manager, error) {
	mgr := &Manager{
		ctx:             ctx,
		debugFilesystem: config.Debug,
		fsMountpoint:    config.Mountpoint,

		mu: &sync.Mutex{},
	}

	switch name := strings.ToLower(config.LoginInterface); name {
	case constant.LoginInterfaceCLI:
		mgr.createLoginHandleFunc = ui.HandleCommandLineLoginInput
	// case constant.LoginInterfaceWeb:
	default:
		return nil, fmt.Errorf("unsupported login interface %q", name)
	}

	names := make(map[string]struct{})
	for _, fsc := range config.Spec {
		if _, ok := names[fsc.PM.Name]; ok {
			return nil, fmt.Errorf("pm name %q already used", fsc.PM.Name)
		}

		names[fsc.PM.Name] = struct{}{}
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
			_ = m.Stop()
		}
	}()

	m.fs, err = CreateFilesystem(m.ctx, m.fsMountpoint, m.debugFilesystem)
	if err != nil {
		return fmt.Errorf("failed to create fuse filesystem: %w", err)
	}

	err = m.fs.Start()
	if err != nil {
		return fmt.Errorf("failed to start fuse filesystem: %w", err)
	}

	for _, b := range m.fsSpec {
		_, _ = fmt.Fprintf(os.Stdout, "Trying to login to %q\n", b.pm.ConfigName())

		err = b.pm.Login(m.createLoginHandleFunc(b.pm.ConfigName()))
		if err != nil {
			return err
		}

		updateCh, err := b.pm.Sync(m.ctx)
		if err != nil {
			return fmt.Errorf("failed to sync pm %q for initialization: %w", b.pm.ConfigName(), err)
		}

		mountFromTo := make(map[string]*conf.MountConfig)

		for i, mount := range b.mounts {
			var data []byte
			data, err = b.pm.Subscribe(mount.From)
			if err != nil {
				return fmt.Errorf("failed to get %q from %q: %w", mount.From, b.pm.ConfigName(), err)
			}

			err = m.fs.BindData(m.ctx, mount.To, data, mount.PermitDuration)
			if err != nil {
				return fmt.Errorf("failed to bind data to filesystem: %w", err)
			}

			mountFromTo[mount.From] = &b.mounts[i]
		}

		_, _ = fmt.Fprintf(os.Stdout, "pm %q login success, credential synced\n", b.pm.ConfigName())

		// flush in memory cache since we don't need to subscribe anymore
		b.pm.Flush()

		if updateCh != nil {
			go m.handlePasswordManagerUpdates(updateCh, mountFromTo)
		}
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

func (m *Manager) handlePasswordManagerUpdates(
	updateCh <-chan pm.CredentialUpdate,
	mounts map[string]*conf.MountConfig,
) {
	for {
		select {
		case <-m.ctx.Done():
			return
		case update := <-updateCh:
			if update.NotSynced {
				// TODO: handle dirty files
				_ = update.Key
				continue
			}

			spec := mounts[update.Key]
			if spec == nil || spec.From != update.Key {
				// defensive check
				// TODO: log unexpected spec nil
				_ = spec
				continue
			}

			err := m.fs.BindData(m.ctx, spec.To, update.NewValue, spec.PermitDuration)
			if err != nil {
				// TODO: log error
				_ = err

				continue
			}
		}
	}
}
