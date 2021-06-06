package security

func init() {
	// set as default to avoid failure
	RegisterAuthorizationHandler(
		"",
		func(config interface{}) (AuthorizationHandler, error) {
			return &nopAuthHandler{}, nil
		},
		func() interface{} { return &nopAuthHandlerConfig{} },
	)
}

type nopAuthHandlerConfig struct{}

type nopAuthHandler struct{}

func (nopAuthHandler) Request(authReqKey, prompt string) (AuthorizationData, error) {
	return nil, nil
}

func (nopAuthHandler) Destroy(d AuthorizationData) error {
	return nil
}
