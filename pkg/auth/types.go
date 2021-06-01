package auth

import "errors"

type loginData struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

var (
	// login data not found, need to request user input
	ErrNotFound = errors.New("not found")

	// old login data invalid, need to request a new one
	ErrOldInvalid = errors.New("old invalid")
)
