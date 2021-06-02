//go:build !darwin
// +build !darwin

package auth

func SaveLogin(pmDriver, configName, username, password string) error {
	return ErrUnsupported
}

func DeleteLogin(pmDriver, configName string) error {
	return ErrUnsupported
}

func GetLogin(pmDriver, configName string) (username, password string, err error) {
	return "", "", ErrUnsupported
}
