//go:build !darwin && !linux
// +build !darwin,!linux

package fs

import (
	"context"
	"fmt"
	"time"

	"arhat.dev/credentialfs/pkg/security"
)

func CreateFilesystem(
	ctx context.Context,
	mountPoint string,
	authHandler security.AuthorizationHandler,
	defaultPenaltyDuration time.Duration,
	defaultPermitDuration time.Duration,
) (Filesystem, error) {
	return nil, fmt.Errorf("unsupported")
}
