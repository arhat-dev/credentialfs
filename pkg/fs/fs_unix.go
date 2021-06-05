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
)

func createFS(ctx context.Context, mountPoint string, debug bool) (_ Filesystem, err error) {
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
		Debug:       debug,
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
	if err != nil && !errors.Is(err, syscall.EINVAL) {
		return nil, fmt.Errorf("failed to encure mountpoint clean: %w", err)
	}

	srv, err := fuse.NewServer(fileFS, mountPoint, &mountOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuse server: %w", err)
	}

	fs := newFilesystem(ctx, mountPoint, root, srv, isTempMount)

	return fs, nil
}

func newFilesystem(
	parentCtx context.Context,
	mountpoint string,
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

		authManager: newAuthManager(ctx),

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

	authManager *authManager

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
	permitDuration time.Duration,
) (err error) {
	fs.mu.Lock()

	ln := newLeafNode(at, data, fs, permitDuration)
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
