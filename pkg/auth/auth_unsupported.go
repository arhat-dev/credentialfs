//go:build !darwin
// +build !darwin

package auth

// RequestAuth requests user authorization
func RequestAuth() (bool, error) {
	return false, ErrUnsupported
}
