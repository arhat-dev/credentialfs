//go:build darwin || linux
// +build darwin linux

package fs

import (
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"sync"
	"syscall"
	"time"

	"arhat.dev/pkg/hashhelper"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"arhat.dev/credentialfs/pkg/security"
)

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

	leafNodes []*leafNode

	mu *sync.RWMutex
}

func (rn *rootNode) addLeafNode(ln *leafNode) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	idx, ok := rn.index[ln.hashedTarget]
	if ok {
		rn.leafNodes[idx] = ln
	} else {
		rn.leafNodes = append(rn.leafNodes, ln)
		rn.index[ln.hashedTarget] = len(rn.leafNodes) - 1
	}
}

func (rn *rootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	result := make([]fuse.DirEntry, len(rn.leafNodes))
	for i, f := range rn.leafNodes {
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

	leafNode := rn.leafNodes[idx]

	return rn.NewInode(ctx, leafNode, fs.StableAttr{
		// Mode: ,
		Ino: uint64(idx) + 2,
	}), 0
}

func newLeafNode(
	to string,
	data []byte,
	fs *filesystem,
	penaltyDuration *time.Duration,
	permitDuration *time.Duration,
) *leafNode {
	return &leafNode{
		fs: fs,

		data: data,

		target:       to,
		hashedTarget: hex.EncodeToString(hashhelper.Sha256Sum(data)),

		penaltyDuration: penaltyDuration,
		permitDuration:  permitDuration,

		usedFds: &sync.Map{},
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

	fs *filesystem

	data []byte

	target       string
	hashedTarget string

	penaltyDuration *time.Duration
	permitDuration  *time.Duration

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
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil, 0, syscall.EACCES
	}

	uidStr := strconv.FormatInt(int64(caller.Uid), 10)
	req, err := security.CreateAuthRequest(
		uidStr, uint64(caller.Pid), security.OpRead, n.target,
	)
	if err != nil {
		return nil, 0, syscall.EACCES
	}

	for i := 10; i < math.MaxInt16; i++ {
		_, loaded := n.usedFds.LoadOrStore(i, struct{}{})
		if !loaded {
			err := n.fs.authManager.RequestAuth(req, n.permitDuration, n.penaltyDuration)
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
	// TODO: how we can handle write operations, we have to work with
	// 		 password managers when writing
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

	leafNode *leafNode
}

func (f *openedLeafNodeFile) Release(ctx context.Context) syscall.Errno {
	f.leafNode.usedFds.Delete(f.fd)
	return 0
}
