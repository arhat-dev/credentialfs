package fs

import (
	"fmt"

	"arhat.dev/credentialfs/pkg/conf"
	"arhat.dev/credentialfs/pkg/pm"
	"github.com/hanwen/go-fuse/v2/fs"
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

func NewManager(config conf.FilesystemConfig) (*Manager, error) {
	mgr := &Manager{}
	for _, fsc := range config {
		pmd, err := pm.NewDriver(fsc.PM.Name, fsc.PM.Config)
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
		// TODO
		_ = b
		requestAuth()
	}

	return nil
}
