//go:build darwin || linux || freebsd
// +build darwin linux freebsd

package fs

import (
	"github.com/hanwen/go-fuse/v2/fs"
)

func init() {
	_ = fs.Inode{}
}
