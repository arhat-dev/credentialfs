//go:build darwin || linux
// +build darwin linux

package fs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"arhat.dev/pkg/hashhelper"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"go.uber.org/multierr"

	"arhat.dev/credentialfs/pkg/auth"
)

func createFS(mountPoint string, debug bool) (_ Filesystem, err error) {
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

	return newFilesystem(mountPoint, root, srv), nil
}

func newFilesystem(mountpoint string, root *rootNode, srv *fuse.Server) *filesystem {
	return &filesystem{
		mountpoint: mountpoint,
		root:       root,
		srv:        srv,

		mu: &sync.Mutex{},
	}
}

type filesystem struct {
	mountpoint string

	stopped uint32

	root *rootNode
	srv  *fuse.Server

	symlinkFiles []string

	mu *sync.Mutex
}

func (fs *filesystem) Start() error {
	go func() {
		defer func() {
			if atomic.LoadUint32(&fs.stopped) == 1 {
				return
			}

			// TODO: log server restart
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

	fs.mu.Lock()
	defer fs.mu.Unlock()

	var err error
	for _, f := range fs.symlinkFiles {
		err = multierr.Append(err, os.Remove(f))
	}

	return multierr.Append(err, fs.srv.Unmount())
}

func (fs *filesystem) BindData(ctx context.Context, at string, data []byte) (err error) {
	fs.mu.Lock()

	ln := newLeafNode(at, data)
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

func newRootNode() *rootNode {
	return &rootNode{
		index: make(map[string]int),
		mu:    &sync.RWMutex{},
	}
}

var (
	_ fs.InodeEmbedder = (*rootNode)(nil)
	_ fs.NodeReaddirer = (*rootNode)(nil)
	_ fs.NodeLookuper  = (*rootNode)(nil)
)

type rootNode struct {
	fs.Inode

	index map[string]int

	credentialFiles []*leafNode

	mu *sync.RWMutex
}

func (rn *rootNode) addLeafNode(ln *leafNode) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	rn.credentialFiles = append(rn.credentialFiles, ln)
	rn.index[ln.hashedTarget] = len(rn.credentialFiles) - 1
}

func (rn *rootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	result := make([]fuse.DirEntry, len(rn.credentialFiles))
	for i, f := range rn.credentialFiles {
		result[i] = fuse.DirEntry{
			Name: f.hashedTarget,
			Ino:  uint64(i) + 2,
			// Mode: fuse.S_IFIFO,
		}
	}

	return fs.NewListDirStream(result), 0
}

func (rn *rootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	idx, ok := rn.index[name]
	if !ok {
		return nil, syscall.ENOENT
	}

	leafNode := rn.credentialFiles[idx]

	return rn.NewInode(ctx, leafNode, fs.StableAttr{
		// Mode: ,
		Ino: uint64(idx) + 2,
	}), 0
}

func newLeafNode(to string, data []byte) *leafNode {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panic(fmt.Errorf("failed to generate random key: %w", err))
	}

	return &leafNode{
		data: data,

		target: to,

		hashedTarget: hex.EncodeToString(hashhelper.Sha256Sum(data)),
		usedFds:      &sync.Map{},
	}
}

var (
	_ fs.InodeEmbedder = (*leafNode)(nil)
	_ fs.NodeStatfser  = (*leafNode)(nil)
	_ fs.NodeGetattrer = (*leafNode)(nil)
	_ fs.NodeOpener    = (*leafNode)(nil)
	_ fs.NodeReader    = (*leafNode)(nil)
)

// leafNode is immutable
type leafNode struct {
	fs.Inode

	data []byte

	target       string
	hashedTarget string

	usedFds *sync.Map
}

func (n *leafNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	return fs.OK
}

func (n *leafNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Size = uint64(len(n.data))
	out.SetTimes(nil, nil, nil)
	return fs.OK
}

func (n *leafNode) Open(ctx context.Context, flags uint32) (fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	for i := 10; i < math.MaxInt16; i++ {
		_, loaded := n.usedFds.LoadOrStore(i, struct{}{})
		if !loaded {
			err := auth.RequestAuth(
				fmt.Sprintf(
					"Your credential in %s is about to be read, please authorize", n.target,
				),
			)
			if err != nil {
				return nil, 0, syscall.EACCES
			}

			return n.newOpenedLeafNodeFile(i), 0, 0
		}
	}

	return nil, 0, syscall.EBUSY
}

func (n *leafNode) Read(ctx context.Context, f fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := off + int64(len(dest))
	if end > int64(len(n.data)) {
		end = int64(len(n.data))
	}

	onf, ok := f.(*openedLeafNodeFile)
	if !ok {
		return nil, syscall.EINVAL
	}

	_, ok = n.usedFds.Load(onf)
	if ok {
		return nil, syscall.EINVAL
	}

	return fuse.ReadResultData(n.data[off:end]), fs.OK
}

func (n *leafNode) Write(
	ctx context.Context, f fs.FileHandle, data []byte, off int64,
) (written uint32, errno syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (n *leafNode) newOpenedLeafNodeFile(fd int) *openedLeafNodeFile {
	return &openedLeafNodeFile{
		fd:       fd,
		leafNode: n,
	}
}

var _ fs.FileReleaser = (*openedLeafNodeFile)(nil)

type openedLeafNodeFile struct {
	fd int

	*leafNode
}

func (f *openedLeafNodeFile) Release(ctx context.Context) syscall.Errno {
	f.leafNode.usedFds.Delete(f.fd)
	return 0
}
