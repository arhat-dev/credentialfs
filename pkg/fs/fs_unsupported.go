//go:build !darwin && !linux
// +build !darwin,!linux

package fs

import (
	"context"
	"fmt"

	"arhat.dev/credentialfs/pkg/security"
)

func CreateFilesystem(
	ctx context.Context,
	mountPoint string,
	authHandler security.AuthorizationHandler,
) (Filesystem, error) {
	return nil, fmt.Errorf("unsupported")
}
