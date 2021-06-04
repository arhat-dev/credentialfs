//go:build !darwin && !linux
// +build !darwin,!linux

package fs

import (
	"context"
	"fmt"
)

func createFS(ctx context.Context, at string, debug bool) (Filesystem, error) {
	return nil, fmt.Errorf("unsupported")
}
