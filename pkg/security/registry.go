package security

type (
	authHandlerKey struct {
		name string
	}
	authHandlerValue struct {
		f  AuthorizationHandlerFactoryFunc
		cf AuthorizationHandlerConfigFactoryFunc
	}
	AuthorizationHandlerFactoryFunc       func(config interface{}) (AuthorizationHandler, error)
	AuthorizationHandlerConfigFactoryFunc func() interface{}
)

var supportedAuthHandlers = make(map[authHandlerKey]*authHandlerValue)

func RegisterAuthorizationHandler(
	name string,
	f AuthorizationHandlerFactoryFunc,
	cf AuthorizationHandlerConfigFactoryFunc,
) {
	supportedAuthHandlers[authHandlerKey{name: name}] = &authHandlerValue{
		f:  f,
		cf: cf,
	}
}

func NewAuthorizationHandlerConfig(name string) (interface{}, error) {
	v, ok := supportedAuthHandlers[authHandlerKey{name: name}]
	if !ok || v == nil {
		return nil, ErrNotFound
	}

	return v.cf(), nil
}

func NewAuthorizationHandler(name string, config interface{}) (AuthorizationHandler, error) {
	v, ok := supportedAuthHandlers[authHandlerKey{name: name}]
	if !ok || v == nil {
		return nil, ErrNotFound
	}

	return v.f(config)
}

type (
	keychainHandleKey struct {
		name string
	}
	keychainHandlerValue struct {
		f  KeychainHandlerFactoryFunc
		cf KeychainHandlerConfigFactoryFunc
	}

	KeychainHandlerFactoryFunc       func(config interface{}) (KeychainHandler, error)
	KeychainHandlerConfigFactoryFunc func() interface{}
)

var supportedKeychainHandlers = make(map[keychainHandleKey]*keychainHandlerValue)

func RegisterKeychainHandler(
	name string,
	f KeychainHandlerFactoryFunc,
	cf KeychainHandlerConfigFactoryFunc,
) {
	supportedKeychainHandlers[keychainHandleKey{name: name}] = &keychainHandlerValue{
		f:  f,
		cf: cf,
	}
}

func NewKeychainHandlerConfig(name string) (interface{}, error) {
	v, ok := supportedKeychainHandlers[keychainHandleKey{name: name}]
	if !ok || v == nil {
		return nil, ErrNotFound
	}

	return v.cf(), nil
}

func NewKeychainHandler(name string, config interface{}) (KeychainHandler, error) {
	v, ok := supportedKeychainHandlers[keychainHandleKey{name: name}]
	if !ok || v == nil {
		return nil, ErrNotFound
	}

	return v.f(config)
}
