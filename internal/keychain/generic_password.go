//go:build darwin && cgo

package keychain

import (
	"fmt"
	"maps"
)

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// GenericPassword are the values for creating or updating a generic
// password keychain entry.
//
// https://developer.apple.com/documentation/security/ksecclassgenericpassword?language=objc
type GenericPassword struct {
	// Account name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattraccount?language=objc
	Account string
	// Service name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattrservice?language=objc
	Service string
	// Label is the user facing label of this item.
	//
	// https://developer.apple.com/documentation/security/ksecattrlabel?language=objc
	Label string
	// Value is the password to store in the keychain. This is only used on
	// creation, it will not be returned on list or lookups.
	//
	// https://developer.apple.com/documentation/security/ksecvaluedata?language=objc
	Value []byte
	// GenericAttributes are the items user-defined attributes.
	//
	// https://developer.apple.com/documentation/security/ksecattrgeneric?language=objc
	GenericAttributes []byte
}

func (g *GenericPassword) toAttributes() C.CFDictionaryRef {
	attrs := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass): C.CFTypeRef(C.kSecClassGenericPassword),
	}

	// TODO - determine what is required or not, and return a proper error

	if g.Account != "" {
		accountRef := stringToCFString(g.Account)
		defer C.CFRelease(C.CFTypeRef(accountRef))
		attrs[C.CFTypeRef(C.kSecAttrAccount)] = C.CFTypeRef(accountRef)
	}
	if g.Service != "" {
		serviceRef := stringToCFString(g.Service)
		defer C.CFRelease(C.CFTypeRef(serviceRef))
		attrs[C.CFTypeRef(C.kSecAttrService)] = C.CFTypeRef(serviceRef)
	}
	if g.Label != "" {
		labelRef := stringToCFString(g.Label)
		defer C.CFRelease(C.CFTypeRef(labelRef))
		attrs[C.CFTypeRef(C.kSecAttrLabel)] = C.CFTypeRef(labelRef)
	}
	if len(g.GenericAttributes) > 0 {
		attrs[C.CFTypeRef(C.kSecAttrGeneric)] = C.CFTypeRef(bytesToCFData(g.GenericAttributes))
	}
	if len(g.Value) > 0 {
		attrs[C.CFTypeRef(C.kSecValueData)] = C.CFTypeRef(bytesToCFData(g.Value))
	}

	return mapToCFDictionary(attrs)
}

func newGenericPasswordFromResult(result map[C.CFTypeRef]C.CFTypeRef) (GenericPassword, error) {
	gpa := GenericPassword{}
	if account, ok := result[C.CFTypeRef(C.kSecAttrAccount)]; ok {
		gpa.Account = stringFromCFString(C.CFStringRef(account))
	}
	if service, ok := result[C.CFTypeRef(C.kSecAttrService)]; ok {
		gpa.Service = stringFromCFString(C.CFStringRef(service))
	}
	if label, ok := result[C.CFTypeRef(C.kSecAttrLabel)]; ok {
		gpa.Label = stringFromCFString(C.CFStringRef(label))
	}
	if generic, ok := result[C.CFTypeRef(C.kSecAttrGeneric)]; ok {
		gpa.GenericAttributes = bytesFromCFData(C.CFDataRef(generic))
	}
	if value, ok := result[C.CFTypeRef(C.kSecValueData)]; ok {
		gpa.Value = bytesFromCFData(C.CFDataRef(value))
	}

	return gpa, nil
}

func CreateGenericPassword(args GenericPassword) error {
	attrs := args.toAttributes()
	defer C.CFRelease(C.CFTypeRef(attrs))

	status := C.SecItemAdd(C.CFDictionaryRef(attrs), nil)
	if err := newKeychainError(status); err != nil {
		return fmt.Errorf("creating generic password: %w", err)
	}

	return nil
}

type GenericPasswordQuery struct {
	// Account name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattraccount?language=objc
	Account string
	// Service name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattrservice?language=objc
	Service string
}

func (g *GenericPasswordQuery) toQueryMap(addlAttrs map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass): C.CFTypeRef(C.kSecClassGenericPassword),
	}

	if g.Account != "" {
		accountRef := stringToCFString(g.Account)
		defer C.CFRelease(C.CFTypeRef(accountRef))
		query[C.CFTypeRef(C.kSecAttrAccount)] = C.CFTypeRef(accountRef)
	}

	if g.Service != "" {
		serviceRef := stringToCFString(g.Service)
		defer C.CFRelease(C.CFTypeRef(serviceRef))
		query[C.CFTypeRef(C.kSecAttrService)] = C.CFTypeRef(serviceRef)
	}

	maps.Copy(query, addlAttrs)

	return mapToCFDictionary(query)
}

func GetGenericPasswordAttributes(query GenericPasswordQuery) (GenericPassword, error) {
	q := query.toQueryMap(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitOne),
	})
	defer C.CFRelease(C.CFTypeRef(q))

	var r C.CFTypeRef
	status := C.SecItemCopyMatching(q, &r)
	if err := newKeychainError(status); err != nil {
		return GenericPassword{}, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(r))

	result := mapFromCFDictionary(C.CFDictionaryRef(r))

	return newGenericPasswordFromResult(result)
}

func GetGenericPassword(query GenericPasswordQuery) ([]byte, error) {
	q := query.toQueryMap(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecReturnData): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitOne),
	})
	defer C.CFRelease(C.CFTypeRef(q))

	var r C.CFTypeRef
	status := C.SecItemCopyMatching(q, &r)
	if err := newKeychainError(status); err != nil {
		return nil, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(r))

	return bytesFromCFData(C.CFDataRef(r)), nil
}

func ListGenericPasswords(query GenericPasswordQuery) ([]GenericPassword, error) {
	q := query.toQueryMap(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitAll),
	})
	defer C.CFRelease(C.CFTypeRef(q))

	var r C.CFTypeRef
	status := C.SecItemCopyMatching(q, &r)
	if err := newKeychainError(status); err != nil {
		return nil, fmt.Errorf("listing generic passwords: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(r))

	result := goSliceFromCFArray(C.CFArrayRef(r))

	passwords := make([]GenericPassword, len(result))
	for i, r := range result {
		var err error
		passwords[i], err = newGenericPasswordFromResult(mapFromCFDictionary(C.CFDictionaryRef(r)))
		if err != nil {
			return nil, fmt.Errorf("listing generic passwords: %w", err)
		}
	}

	return passwords, nil
}

// DeleteGenericPassword deletes all items from the keychain that match the
// query.
func DeleteGenericPassword(query GenericPasswordQuery) error {
	if query.Service == "" && query.Account == "" {
		return fmt.Errorf("cannot delete generic password without service or account")
	}

	q := query.toQueryMap(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
	defer C.CFRelease(C.CFTypeRef(q))

	status := C.SecItemDelete(C.CFDictionaryRef(q))
	if err := newKeychainError(status); err != nil {
		return fmt.Errorf("deleting generic password: %w", err)
	}

	return nil
}
