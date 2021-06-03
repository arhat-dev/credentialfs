package auth

// https://developer.apple.com/documentation/security/authorization_services

/*

#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

OSStatus request_auth(char* right_name, char* prompt, size_t prompt_size) {
	AuthorizationRef ref;
	OSStatus code = AuthorizationCreate(
		NULL,
		kAuthorizationEmptyEnvironment,
		kAuthorizationFlagDefaults,
		&ref);
	if (code != errAuthorizationSuccess) {
		return code;
	}

	AuthorizationItem rightItems[1];
	rightItems[0].name = right_name;
	rightItems[0].value = (char *)("test");
	rightItems[0].valueLength = 5;

	AuthorizationRights rights = {
		.count = sizeof (rightItems) / sizeof (rightItems[0]),
		.items = rightItems,
	};

	AuthorizationItem envItems[1];
	envItems[0].name = kAuthorizationEnvironmentPrompt;
	envItems[0].value = prompt;
	envItems[0].valueLength = prompt_size;

	AuthorizationEnvironment env = {
		.count = sizeof (envItems) / sizeof (envItems[0]),
		.items = envItems,
	};

	code = AuthorizationCreate(
		&rights,
		&env,
		kAuthorizationFlagDefaults | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights,
		&ref);

	free(right_name);
	free(prompt);

	if (code == errAuthorizationSuccess) {
		AuthorizationFree(ref, kAuthorizationFlagDestroyRights);
	}

	return code;
}

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

// RequestAuth requests user authorization from Authorization Service
func RequestAuth(prompt string) error {
	code := C.request_auth(
		C.CString("dev.arhat.credentialfs.file.read"),
		C.CString(prompt),
		C.size_t(len(prompt)),
	)

	switch code {
	case authSuccess:
		return nil
	case authUserDenied:
		return fmt.Errorf("authorization denied by user")
	case authUserCancled:
		return fmt.Errorf("authorization canceled by user")
	default:
		return fmt.Errorf("authorization failed: %d", code)
	}
}
