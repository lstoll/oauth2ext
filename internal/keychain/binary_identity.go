//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

*/
import "C"
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unsafe"
)

var preferredCDHashes = []CodeSignatureHash{
	CodeSignatureHashSHA256,
	CodeSignatureHashSHA256Truncated,
	CodeSignatureHashSHA384,
	CodeSignatureHashSHA512,
	CodeSignatureHashSHA1,
}

// GetBinaryIdentity returns a unique identifier for the current binary. This
// can be used to key items for use by this build of the app only, ignoring them
// silently if the binary changes. This is useful in ad-hoc/temporary items, to
// avoid prompting the user to unlock the keychain when reading a secret. By
// default on ARM platforms all binaries must be codesigned, which may be an
// ad-hoc or formal signature. If the binary is signed, this will return the
// code signing hash. If the binary is unsigned or verification fails, this will
// return the SHA-256 hash of the executable file.
func GetBinaryIdentity() (string, error) {
	// TODO - handle legit code-signed binaries, and use something consistent
	// across versions of them.

	// First, try the preferred method: getting the OS-level CDHash.
	cdHashes, err := getSelfCDHashes()
	if err == nil {
		for _, hash := range preferredCDHashes {
			if cdHash, ok := cdHashes[hash]; ok {
				return cdHash, nil
			}
		}
	}

	// if that fails, fallback to the executable file hash
	return hashExecutableFile()
}

// hashExecutableFile calculates the SHA-256 hash of the current executable file.
func hashExecutableFile() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}

	f, err := os.Open(execPath)
	if err != nil {
		return "", fmt.Errorf("os.Open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("io.Copy: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

type CodeSignatureHash string

const (
	CodeSignatureHashSHA1            CodeSignatureHash = "sha1"
	CodeSignatureHashSHA256          CodeSignatureHash = "sha256"
	CodeSignatureHashSHA256Truncated CodeSignatureHash = "sha256_truncated"
	CodeSignatureHashSHA384          CodeSignatureHash = "sha384"
	CodeSignatureHashSHA512          CodeSignatureHash = "sha512"
)

// getSelfCDHashes retrieves a map of all Code Directory Hashes (CDHashes) for
// the running binary, keyed by their digest algorithm type.
func getSelfCDHashes() (map[CodeSignatureHash]string, error) {
	// Get a reference to the static code of the currently running process.
	var myselfCode C.SecCodeRef
	status := C.SecCodeCopySelf(C.kSecCSDefaultFlags, &myselfCode)
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("failed to get SecCodeRef for self (error code: %d)", status)
	}
	defer C.CFRelease(C.CFTypeRef(myselfCode))

	// Validate the code signature first, to see if we're signed and it's valid.
	// If not, we can fallback later.
	status = C.SecCodeCheckValidity(myselfCode, C.kSecCSDefaultFlags, nilSecRequirementRef)
	if status != C.errSecSuccess {
		return nil, &Error{
			Code: ErrorCode(status),
		}
	}

	// Get the code signing information dictionary.
	var signingInfo C.CFDictionaryRef
	status = C.SecCodeCopySigningInformation(C.SecStaticCodeRef(myselfCode), C.kSecCSDefaultFlags, &signingInfo)
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("failed to copy signing information (error code: %d)", status)
	}
	defer C.CFRelease(C.CFTypeRef(signingInfo))

	signingInfoMap := mapFromCFDictionary(signingInfo)

	hashesPtr, hashesOk := signingInfoMap[C.CFTypeRef(C.kSecCodeInfoCdHashes)]
	algsPtr, algsOk := signingInfoMap[C.CFTypeRef(C.kSecCodeInfoDigestAlgorithms)]

	if !hashesOk || !algsOk {
		return nil, fmt.Errorf("kSecCodeInfoCdHashes or kSecCodeInfoDigestAlgorithms key not found")
	}

	if C.CFGetTypeID(C.CFTypeRef(hashesPtr)) != C.CFArrayGetTypeID() || C.CFGetTypeID(C.CFTypeRef(algsPtr)) != C.CFArrayGetTypeID() {
		return nil, fmt.Errorf("hashes or algorithms value is not a CFArray")
	}

	hashesArray := C.CFArrayRef(hashesPtr)
	algsArray := C.CFArrayRef(algsPtr)

	hashesSlice := goSliceFromCFArray(hashesArray)
	algsSlice := goSliceFromCFArray(algsArray)

	if len(hashesSlice) != len(algsSlice) {
		return nil, fmt.Errorf("hashes and algorithms arrays have different lengths")
	}
	if len(hashesSlice) < 1 {
		return nil, fmt.Errorf("no hashes found in signing information")
	}

	resultMap := make(map[CodeSignatureHash]string)
	for i := range hashesSlice {
		algPtr := algsSlice[i]
		if C.CFGetTypeID(C.CFTypeRef(algPtr)) != C.CFNumberGetTypeID() {
			continue // Skip if not a number
		}
		var algID C.int
		C.CFNumberGetValue(C.CFNumberRef(algPtr), C.kCFNumberIntType, unsafe.Pointer(&algID))

		hashPtr := hashesSlice[i]
		if C.CFGetTypeID(C.CFTypeRef(hashPtr)) != C.CFDataGetTypeID() {
			continue // Skip if not data
		}
		hashData := C.CFDataRef(hashPtr)

		hashBytes := bytesFromCFData(hashData)
		if len(hashBytes) > 0 {
			algName, err := mapAlgorithmIDToString(algID)
			if err != nil {
				return nil, fmt.Errorf("failed to map algorithm ID to string: %w", err)
			}
			resultMap[algName] = hex.EncodeToString(hashBytes)
		}
	}

	return resultMap, nil
}

// mapAlgorithmIDToString converts a macOS digest algorithm constant to a string.
func mapAlgorithmIDToString(algID C.int) (CodeSignatureHash, error) {
	switch algID {
	case C.kSecCodeSignatureHashSHA1:
		return CodeSignatureHashSHA1, nil
	case C.kSecCodeSignatureHashSHA256:
		return CodeSignatureHashSHA256, nil
	case C.kSecCodeSignatureHashSHA256Truncated:
		return CodeSignatureHashSHA256Truncated, nil
	case C.kSecCodeSignatureHashSHA384:
		return CodeSignatureHashSHA384, nil
	case C.kSecCodeSignatureHashSHA512:
		return CodeSignatureHashSHA512, nil
	default:
		return "", fmt.Errorf("unknown code signature hash algorithm: %d", algID)
	}
}
