package auth

import "errors"

// nolint:unused,deadcode
type loginData struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

// Errors require special handling
// nolint:revive
var (
	// login data not found, need to request user input
	ErrNotFound = errors.New("not found")

	// old login data invalid, need to request a new one
	ErrOldInvalid = errors.New("old invalid")

	// operation not supported
	ErrUnsupported = errors.New("not supported")
)

// AuthorizationData returned by system security service
// for darwin, it's a C pointer value for AuthorizationRef
type AuthorizationData interface{}
