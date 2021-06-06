package fs

import (
	"context"
	"time"
)

// nolint:revive
const (
	FilesystemName = "credentialfs"
)

type Filesystem interface {
	// Start serving files in background (mount)
	Start() error

	// Stop background serving (unmount)
	Stop() error

	BindData(
		ctx context.Context,
		at string,
		data []byte,
		penaltyDuration *time.Duration,
		permitDuration *time.Duration,
	) error
}
