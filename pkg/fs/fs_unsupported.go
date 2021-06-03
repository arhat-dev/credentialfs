//go:build !darwin && !linux
// +build !darwin,!linux

package fs

import (
	"fmt"
)

func createFS(at string, debug bool) (Filesystem, error) {
	return nil, fmt.Errorf("unsupported")
}
