//go:build !test
// +build !test

package system

import (
	"fmt"
	"sync"

	"arhat.dev/credentialfs/pkg/security"
	"github.com/mritd/touchid"
)

func init() {
	// for darwin, it should be the default auth handler
	security.RegisterAuthorizationHandler("", newAuthHandler, newAuthHandlerConfig)
	security.RegisterAuthorizationHandler("system", newAuthHandler, newAuthHandlerConfig)
}

func newAuthHandlerConfig() interface{} { return &config{} }

type config struct{}

func newAuthHandler(config interface{}) (security.AuthorizationHandler, error) {
	_ = config
	// TODO: check system support for TouchID
	return &authHandler{mu: &sync.Mutex{}, canTouchID: true}, nil
}

type authHandler struct {
	// seralize requests
	mu *sync.Mutex

	canTouchID bool
}

func (s *authHandler) Authorize(req *security.AuthRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ok, err := touchid.Auth(touchid.DeviceTypeAny, req.FormatPrompt())
	if err != nil {
		return fmt.Errorf("authorization request failed: %w", err)
	}

	if !ok {
		return fmt.Errorf("authorization denied by user")
	}

	return nil
}
