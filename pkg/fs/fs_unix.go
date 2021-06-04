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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"go.uber.org/multierr"
)

func createFS(ctx context.Context, mountPoint string, debug bool) (_ Filesystem, err error) {
	root := newRootNode()

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

	fs := newFilesystem(ctx, mountPoint, root, srv)

	return fs, nil
}

func newFilesystem(
	parentCtx context.Context,
	mountpoint string,
	root *rootNode,
	srv *fuse.Server,
) *filesystem {
	ctx, cancel := context.WithCancel(parentCtx)

	return &filesystem{
		ctx:    ctx,
		cancel: cancel,

		mountpoint: mountpoint,

		started: 0,
		stopped: 0,

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

	mountpoint string

	started uint32
	stopped uint32

	root *rootNode
	srv  *fuse.Server

	symlinkFiles []string

	authManager *authManager

	mu *sync.Mutex
}

func (fs *filesystem) Start() error {
	if atomic.CompareAndSwapUint32(&fs.started, 0, 1) {
		// do once

		fs.authManager.Start()
	}

	go func() {
		defer func() {
			if atomic.LoadUint32(&fs.stopped) == 1 {
				return
			}

			// TODO: log fuse server restart
			_ = fs.Start()
		}()

		fs.srv.Serve()
	}()

	return nil
}

// Stop background serving (unmount)
func (fs *filesystem) Stop() error {
	if !atomic.CompareAndSwapUint32(&fs.stopped, 0, 1) {
		// already stopped
		return nil
	}

	fs.cancel()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	var err error
	for _, f := range fs.symlinkFiles {
		err = multierr.Append(err, os.Remove(f))
	}

	err = multierr.Append(err, fs.authManager.Stop())

	return multierr.Append(err, fs.srv.Unmount())
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
			return err
		}
	}

	fs.symlinkFiles = append(fs.symlinkFiles, at)

	return nil
}
