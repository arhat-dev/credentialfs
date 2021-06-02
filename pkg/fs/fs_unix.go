//go:build darwin || linux
// +build darwin linux

package fs

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

func init() {
	_ = fs.Inode{}
}
