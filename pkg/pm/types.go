package pm

import "context"

type TwoFactorKind string

// nolint:revive
const (
	// TwoFactorKindNone means no two factor authentication
	// requires user input for username and password
	TwoFactorKindNone TwoFactorKind = ""

	// TwoFactorKindOTP means one time password, provided via sms/email/auth
	// requires user input for username, password, and the one time password
	TwoFactorKindOTP = "otp"

	TwoFactorKindFIDO  = "fido"
	TwoFactorKindFIDO2 = "fido2" // also: WebAuthn
	TwoFactorKindU2F   = "u2f"
)

type LoginInput struct {
	Username []byte
	Password []byte

	ValueFor2FA []byte
}

// LoginInputCallbackFunc used for requesting login input
//
// when the currentInput is not nil, the returned *LoginInput should remain
// the same with inner field value updated according to existing values
type LoginInputCallbackFunc func(t TwoFactorKind, currentInput *LoginInput) (*LoginInput, error)

type Interface interface {
	DriverName() string

	ConfigName() string

	Login(requestUserLogin LoginInputCallbackFunc) error

	// Sync with password manager, this will build a in memory cache of all
	// credentials from password manager
	//
	// The returned channel can be nil if the implementation has no support
	// for continuous credential syncing
	//
	// The value of returned channel is always the same
	Sync(ctx context.Context) (<-chan CredentialUpdate, error)

	// Subscribe looks up in memory cahe of all credentials with the key
	// returns the cached value of the key if found
	//
	// The key format is implementation specific
	//
	// This method will return error if there is no in memory cache
	Subscribe(key string) ([]byte, error)

	// Flush previously built in memory cache
	Flush()

	Update(key string, data []byte) error
}

// Common index keys
const (
	IndexKeyUsername = "username"
	IndexKeyPassword = "password"
)

// CredentialUpdate represents a update meesage for subscriber
type CredentialUpdate struct {
	// Key provided when the receiver
	Key string

	// NotSynced is set to true when we observed the upstream data have changed
	// but we could not fetch the updated data in time, to notify the receiver
	// of this update that the exiting data may not be read
	NotSynced bool

	// NewValue is not nil when NotSynced is false, it is the latest value
	NewValue []byte
}
