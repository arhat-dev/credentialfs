//go:build !darwin
// +build !darwin

package auth

// RequestAuthorization requests user authorization
func RequestAuthorization(key, prompt string) error {
	return nil
}

// DestroyAuthorization
func DestroyAuthorization(d AuthorizationData) error {
	return nil
}
