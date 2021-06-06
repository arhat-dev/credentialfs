package security

import "errors"

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

// AuthorizationData returned by security service
type AuthorizationData interface{}

type AuthorizationHandler interface {
	// Request explicit user authorization
	Request(authReqKey, prompt string) (AuthorizationData, error)

	// Destroy granted authorization
	Destroy(d AuthorizationData) error
}

type KeychainHandler interface {
	// SaveLogin saves username and password to system keychain
	SaveLogin(pmDriver, configName, username, password string) error

	// DeleteLogin deletes stored username and password
	DeleteLogin(pmDriver, configName string) error

	// GetLogin retrieves previously stored username and password
	GetLogin(pmDriver, configName string) (username, password string, err error)
}
