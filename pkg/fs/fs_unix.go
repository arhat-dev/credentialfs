//go:build darwin || linux
// +build darwin linux

package fs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"go.uber.org/multierr"

	"arhat.dev/credentialfs/pkg/constant"
	"arhat.dev/credentialfs/pkg/security"
)

func CreateFilesystem(
	ctx context.Context,
	mountPoint string,
	authHandler security.AuthorizationHandler,
	defaultPenaltyDuration time.Duration,
	defaultPermitDuration time.Duration,
) (_ Filesystem, err error) {
	isTempMount := false

	if len(mountPoint) == 0 {
		mountPoint, err = os.MkdirTemp(os.TempDir(), "cfs-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary mountpoint: %w", err)
		}

		isTempMount = true
		defer func() {
			if err != nil {
				_ = os.Remove(mountPoint)
			}
		}()
	}

	var options []string
	switch runtime.GOOS {
	case "darwin":
		// TODO
		_ = options
	case "linux":
		// TODO
		_ = options
	}

	mountOpts := fuse.MountOptions{
		Debug:       constant.DebugEnabled(ctx),
		Options:     options,
		DirectMount: false,
		FsName:      mountPoint,
		Name:        FilesystemName,
		AllowOther:  true,
	}

	root := newRootNode()
	fileFS := fs.NewNodeFS(root, &fs.Options{
		MountOptions: mountOpts,
		OnAdd:        func(ctx context.Context) {},
	})

	err = syscall.Unmount(mountPoint, 0)
	if err != nil {
		if !errors.Is(err, syscall.EINVAL) &&
			// permission error on macos big sur
			!errors.Is(err, syscall.EPERM) {
			return nil, fmt.Errorf("failed to encure mountpoint clean: %w", err)
		}
	}

	srv, err := fuse.NewServer(fileFS, mountPoint, &mountOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuse server: %w", err)
	}

	fs := newFilesystem(
		ctx,
		mountPoint,
		authHandler,
		defaultPenaltyDuration,
		defaultPermitDuration,
		root,
		srv,
		isTempMount,
	)

	return fs, nil
}

func newFilesystem(
	parentCtx context.Context,
	mountpoint string,
	authHandler security.AuthorizationHandler,
	defaultPenaltyDuration time.Duration,
	defaultPermitDuration time.Duration,
	root *rootNode,
	srv *fuse.Server,
	isTempMount bool,
) *filesystem {
	ctx, cancel := context.WithCancel(parentCtx)

	return &filesystem{
		ctx:    ctx,
		cancel: cancel,

		mountpoint:  mountpoint,
		isTempMount: isTempMount,

		root: root,
		srv:  srv,

		symlinkFiles: nil,

		authManager: security.NewAuthorizationManager(
			ctx, authHandler,
			defaultPenaltyDuration,
			defaultPermitDuration,
		),

		mu: &sync.Mutex{},
	}
}

type filesystem struct {
	ctx    context.Context
	cancel context.CancelFunc

	mountpoint  string
	isTempMount bool

	root *rootNode
	srv  *fuse.Server

	symlinkFiles []string

	authManager *security.AuthorizationManager

	mu *sync.Mutex
}

func (fs *filesystem) startFUSEServerUntilFilesystemStopped() {
	go func() {
		defer func() {
			select {
			case <-fs.ctx.Done():
				return
			default:
			}

			// TODO: log fuse server restart
			fs.startFUSEServerUntilFilesystemStopped()
		}()

		fs.srv.Serve()
	}()
}

func (fs *filesystem) Start() error {
	fs.authManager.Start()
	fs.startFUSEServerUntilFilesystemStopped()

	return nil
}

// Stop background serving (unmount)
func (fs *filesystem) Stop() error {
	fs.cancel()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	var err error

	err = multierr.Append(err, fs.authManager.Stop())
	err = multierr.Append(err, fs.srv.Unmount())

	// usually system will remove these symlinks on fuse unmounted
	// just remove expicitly to ensure
	for _, f := range fs.symlinkFiles {
		err2 := os.Remove(f)
		if err2 != nil && !os.IsNotExist(err2) {
			err = multierr.Append(err, err2)
		}
	}

	if fs.isTempMount {
		err = multierr.Append(err, os.RemoveAll(fs.mountpoint))
	}

	return err
}

func (fs *filesystem) BindData(
	ctx context.Context,
	at string,
	data []byte,
	penaltyDuration *time.Duration,
	permitDuration *time.Duration,
) (err error) {
	fs.mu.Lock()

	ln := newLeafNode(at, data, fs, penaltyDuration, permitDuration)
	fs.root.addLeafNode(ln)

	fs.mu.Unlock()

	realPath := filepath.Join(fs.mountpoint, ln.hashedTarget)
	err = os.Symlink(realPath, ln.target)
	if err != nil {
		if !os.IsExist(err) {
			return err
		}

		// check if it's a symlink
		linkInfo, err2 := os.Lstat(ln.target)
		if err2 != nil {
			return err
		}

		if linkInfo.Mode()&os.ModeSymlink == 0 {
			return err
		}

		err = os.Remove(ln.target)
		if err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}

		err = os.Symlink(realPath, ln.target)
		if err != nil {
			return fmt.Errorf("failed to recreate symlink: %w", err)
		}
	}

	fs.symlinkFiles = append(fs.symlinkFiles, at)

	return nil
}
