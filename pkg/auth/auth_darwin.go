package auth

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
)

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

// RequestAuthorization requests user authorization via macos Authorization Service
func RequestAuthorization(key, prompt string) (AuthorizationData, error) {
	ref_ptr := C.create_auth_ref_ptr()

	code := C.request_auth(
		C.CString(key),
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

func DestroyAuthorization(d AuthorizationData) error {
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
