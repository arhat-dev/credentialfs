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

func (nopAuthHandler) Authorize(req *AuthRequest) error {
	return nil
}
