//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import "fmt"

type ErrorCode int

const (
	KeychainErrorCodeSuccess       ErrorCode = C.errSecSuccess
	KeychainErrorCodeDuplicateItem ErrorCode = C.errSecDuplicateItem
	KeychainErrorCodeItemNotFound  ErrorCode = C.errSecItemNotFound
)

type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string {
	cfError := C.SecCopyErrorMessageString(C.OSStatus(e.Code), nil)
	if cfError != nilCFStringRef {
		defer C.CFRelease(C.CFTypeRef(cfError))
		return fmt.Sprintf("%s (%d)", stringFromCFString(cfError), e.Code)
	}
	return fmt.Sprintf("Unknown keychain error: %d", e.Code)
}

func newKeychainError(status C.OSStatus) error {
	if status == C.errSecSuccess {
		return nil
	}
	return &Error{
		Code: ErrorCode(status),
	}
}
