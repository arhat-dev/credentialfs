package fs

import "context"

const (
	FilesystemName = "credentialfs"
)

type Filesystem interface {
	// Start serving files in background (mount)
	Start() error

	// Stop background serving (unmount)
	Stop() error

	BindData(ctx context.Context, at string, data []byte) error
}

func CreateFilesystem(at string, debug bool) (Filesystem, error) {
	return createFS(at, debug)
}
