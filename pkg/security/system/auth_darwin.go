//go:build !test
// +build !test

package system

// https://developer.apple.com/documentation/security/authorization_services

/*

#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "auth_darwin.h"

*/
import "C"
import (
	"fmt"
	"sync"

	"arhat.dev/credentialfs/pkg/security"
)

func init() {
	// for darwin, it should be the default auth handler
	security.RegisterAuthorizationHandler("", newAuthHandler, newAuthHandlerConfig)
	security.RegisterAuthorizationHandler("system", newAuthHandler, newAuthHandlerConfig)
}

func newAuthHandlerConfig() interface{} { return &config{} }

type config struct{}

// nolint:deadcode,varcheck
const (
	authSuccess               = C.errAuthorizationSuccess
	authInvalidSet            = C.errAuthorizationInvalidSet
	authInvalidRef            = C.errAuthorizationInvalidRef
	authInvalidTag            = C.errAuthorizationInvalidTag
	authInvalidRightPointer   = C.errAuthorizationInvalidPointer
	authUserDenied            = C.errAuthorizationDenied
	authUserCancled           = C.errAuthorizationCanceled
	authServerDenied          = C.errAuthorizationInteractionNotAllowed
	authInternalErr           = C.errAuthorizationInternal
	authExternalizeNotAllowed = C.errAuthorizationExternalizeNotAllowed
	authInternalizeNotAllowed = C.errAuthorizationInternalizeNotAllowed
	authInvalidFlags          = C.errAuthorizationInvalidFlags
	authToolExecuteFailure    = C.errAuthorizationToolExecuteFailure
	authToolEnvironmentError  = C.errAuthorizationToolEnvironmentError
	authBadAddress            = C.errAuthorizationBadAddress
)

func newAuthHandler(config interface{}) (security.AuthorizationHandler, error) {
	_ = config
	// TODO: check system support
	return &authHandler{mu: &sync.Mutex{}}, nil
}

type authHandler struct {
	// seralize requests
	mu *sync.Mutex
}

func (s *authHandler) Request(authReqKey, prompt string) (security.AuthorizationData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref_ptr := C.create_auth_ref_ptr()

	code := C.request_auth(
		C.CString(authReqKey),
		C.CString(prompt),
		C.size_t(len(prompt)),
		ref_ptr,
	)

	switch code {
	case authSuccess:
		return ref_ptr, nil
	case authUserDenied:
		return nil, fmt.Errorf("authorization denied by user")
	case authUserCancled:
		return nil, fmt.Errorf("authorization canceled by user")
	default:
		return nil, fmt.Errorf("authorization failed: code %d", code)
	}
}

func (s *authHandler) Destroy(d security.AuthorizationData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ref_ptr, ok := d.(*C.AuthorizationRef)
	if !ok {
		return fmt.Errorf("invalid authorization data type: %T", d)
	}

	code := C.destroy_auth(ref_ptr)

	switch code {
	case 0:
		return nil
	default:
		return fmt.Errorf("failed to destroy authorization: code %d", code)
	}
}
