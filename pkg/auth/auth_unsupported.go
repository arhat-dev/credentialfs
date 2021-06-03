//go:build !darwin
// +build !darwin

package auth

// RequestAuth requests user authorization
func RequestAuth(prompt string) error {
	return ErrUnsupported
}
