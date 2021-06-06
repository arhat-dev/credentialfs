package pm

import (
	"context"
	"fmt"

	"arhat.dev/credentialfs/pkg/security"
)

type (
	ConfigFactoryFunc func() interface{}
	FactoryFunc       func(
		ctx context.Context,
		configName string,
		config interface{},
		keychainHandler security.KeychainHandler,
	) (Interface, error)
)

type bundle struct {
	f  FactoryFunc
	cf ConfigFactoryFunc
}

var (
	supportedDrivers = map[string]*bundle{}
)

func Register(name string, f FactoryFunc, cf ConfigFactoryFunc) {
	if f == nil || cf == nil {
		return
	}

	// reserve empty name
	if name == "" {
		return
	}

	supportedDrivers[name] = &bundle{
		f:  f,
		cf: cf,
	}
}

func NewConfig(name string) (interface{}, error) {
	b, ok := supportedDrivers[name]
	if !ok {
		return nil, fmt.Errorf("driver %q not found", name)
	}

	return b.cf(), nil
}

func NewDriver(
	ctx context.Context,
	driverName string,
	configName string,
	config interface{},
	keychainHandler security.KeychainHandler,
) (Interface, error) {
	b, ok := supportedDrivers[driverName]
	if !ok {
		return nil, fmt.Errorf("driver %q not found", driverName)
	}

	return b.f(ctx, configName, config, keychainHandler)
}
