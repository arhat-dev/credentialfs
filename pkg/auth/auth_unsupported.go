//go:build !darwin
// +build !darwin

package auth

// RequestAuthorization requests user authorization
func RequestAuthorization(key, prompt string) (AuthorizationData, error) {
	return nil, nil
}

// DestroyAuthorization
func DestroyAuthorization(d AuthorizationData) error {
	return nil
}
