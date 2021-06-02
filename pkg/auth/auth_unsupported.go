//go:build !darwin
// +build !darwin

package auth

// request user authorization from Authorization Service
func RequestAuth() (bool, error) {
	return false, ErrUnsupported
}
