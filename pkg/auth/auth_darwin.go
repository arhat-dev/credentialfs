package auth

// https://developer.apple.com/documentation/security/authorization_services

/*

#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

*/
import "C"
import (
	"fmt"
)

// request user authorization from Authorization Service
func RequestAuth() (bool, error) {
	return false, fmt.Errorf("unimplemented")
}
