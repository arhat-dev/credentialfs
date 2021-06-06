package security

func init() {
	// set as default to avoid failure
	RegisterKeychainHandler(
		"",
		func(config interface{}) (KeychainHandler, error) {
			return &nopKeychainHandler{}, nil
		},
		func() interface{} { return &nopKeychainHandlerConfig{} },
	)
}

type nopKeychainHandlerConfig struct{}

type nopKeychainHandler struct{}

func (nopKeychainHandler) SaveLogin(pmDriver, configName, username, password string) error {
	return nil
}

func (nopKeychainHandler) DeleteLogin(pmDriver, configName string) error {
	return nil
}

func (nopKeychainHandler) GetLogin(pmDriver, configName string) (username, password string, err error) {
	return "", "", nil
}
