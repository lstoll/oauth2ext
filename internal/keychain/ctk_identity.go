//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os/exec"
)

/* CTK identities created with: sc_auth create-ctk-identity -l <label> -k p-256-ne -t none */

// CTKCardTokenID is the token ID for CTK smart card identities created with
// sc_auth create-ctk-identity. These keys are stored in the Secure Enclave
// but accessed via the CryptoTokenKit card emulation layer.
const CTKCardTokenID = "com.apple.ctkcard:user"

// CTKKeyType represents the key algorithm for CTK identities.
type CTKKeyType string

const (
	// CTKKeyTypeP256 creates a P-256 (secp256r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP256 CTKKeyType = "p-256-ne"
	// CTKKeyTypeP384 creates a P-384 (secp384r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP384 CTKKeyType = "p-384-ne"
)

// CreateCTKIdentity creates a new CTK identity with the given label and key type.
// This shells out to sc_auth create-ctk-identity.
// Returns the created identity (without signing capability - use GetCTKIdentity for that).
// Note: Multiple identities can have the same label.
func CreateCTKIdentity(label string, keyType CTKKeyType) (*CTKIdentity, error) {
	if label == "" {
		return nil, fmt.Errorf("label is required")
	}
	if keyType == "" {
		keyType = CTKKeyTypeP256
	}

	// Get existing identity hashes before creation
	beforeList, err := ListCTKIdentities()
	if err != nil {
		return nil, fmt.Errorf("listing identities before creation: %w", err)
	}
	existingHashes := make(map[string]bool)
	for _, id := range beforeList {
		existingHashes[hex.EncodeToString(id.PublicKeyHash)] = true
	}

	// Create the identity
	cmd := exec.Command("sc_auth", "create-ctk-identity", "-l", label, "-k", string(keyType), "-t", "none")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc_auth create-ctk-identity failed: %w: %s", err, string(output))
	}

	// Get identities after creation and find the new one
	afterList, err := ListCTKIdentities()
	if err != nil {
		return nil, fmt.Errorf("listing identities after creation: %w", err)
	}

	for _, id := range afterList {
		hashHex := hex.EncodeToString(id.PublicKeyHash)
		if !existingHashes[hashHex] && id.Label == label {
			return &CTKIdentity{
				Label:         id.Label,
				PublicKeyHash: id.PublicKeyHash,
				TokenID:       id.TokenID,
				KeySizeInBits: id.KeySizeInBits,
			}, nil
		}
	}

	return nil, fmt.Errorf("created identity but could not find it in keychain")
}

// DeleteCTKIdentity deletes a CTK identity by its public key hash.
// This shells out to sc_auth delete-ctk-identity.
func DeleteCTKIdentity(publicKeyHash []byte) error {
	if publicKeyHash == nil {
		return fmt.Errorf("publicKeyHash is required")
	}

	hashHex := hex.EncodeToString(publicKeyHash)
	cmd := exec.Command("sc_auth", "delete-ctk-identity", "-h", hashHex)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc_auth delete-ctk-identity failed: %w: %s", err, string(output))
	}

	return nil
}

// DeleteCTKIdentityByLabel deletes a CTK identity by its label.
// Returns an error if multiple identities have the same label.
func DeleteCTKIdentityByLabel(label string) error {
	identity, err := GetCTKIdentity(label, nil)
	if err != nil {
		return fmt.Errorf("finding identity to delete: %w", err)
	}
	defer identity.Close()

	return DeleteCTKIdentity(identity.PublicKeyHash)
}

// CTKIdentity represents a CryptoTokenKit identity created with sc_auth,
// typically backed by the Secure Enclave.
type CTKIdentity struct {
	// Label is the user-facing label of this identity.
	Label string
	// PublicKeyHash is the SHA-1 hash of the public key (shown by sc_auth list-ctk-identities).
	PublicKeyHash []byte
	// TokenID identifies the token that stores this key.
	TokenID string
	// KeySizeInBits is the size of the key in bits.
	KeySizeInBits int

	// secKeyRef holds the SecKeyRef for the private key. Only set when
	// retrieved via GetCTKIdentity.
	secKeyRef C.SecKeyRef
}

// Close releases the underlying SecKeyRef if it was retrieved.
// This should be called when the identity is no longer needed.
func (c *CTKIdentity) Close() {
	if c.secKeyRef != nilSecKeyRef {
		C.CFRelease(C.CFTypeRef(c.secKeyRef))
		c.secKeyRef = nilSecKeyRef
	}
}

// Signer returns the private key as a crypto.Signer. The key is backed by
// the Secure Enclave and cannot be exported. The identity must have been
// retrieved via GetCTKIdentity.
func (c *CTKIdentity) Signer() (crypto.Signer, error) {
	if c.secKeyRef == nilSecKeyRef {
		return nil, fmt.Errorf("no key ref available; use GetCTKIdentity to retrieve a signable identity")
	}

	// Determine the curve from key size
	var curve elliptic.Curve
	switch c.KeySizeInBits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key size: %d bits", c.KeySizeInBits)
	}

	// Get the public key from the private key ref
	pubKeyRef := C.SecKeyCopyPublicKey(c.secKeyRef)
	if pubKeyRef == nilSecKeyRef {
		return nil, fmt.Errorf("failed to get public key from private key")
	}
	defer C.CFRelease(C.CFTypeRef(pubKeyRef))

	// Export the public key as external representation
	var cfError C.CFErrorRef
	pubKeyData := C.SecKeyCopyExternalRepresentation(pubKeyRef, &cfError)
	if pubKeyData == nilCFDataRef {
		return nil, fmt.Errorf("failed to export public key")
	}
	defer C.CFRelease(C.CFTypeRef(pubKeyData))

	pubKeyBytes := bytesFromCFData(pubKeyData)

	// Parse the public key using the standard library
	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &secKeyPrivateKey{
		keyRef: c.secKeyRef,
		pub:    pubKey,
	}, nil
}

// secKeyPrivateKey implements crypto.Signer using a SecKeyRef.
type secKeyPrivateKey struct {
	keyRef C.SecKeyRef
	pub    *ecdsa.PublicKey
}

func (s *secKeyPrivateKey) Public() crypto.PublicKey {
	return s.pub
}

func (s *secKeyPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var algorithm C.SecKeyAlgorithm
	switch opts.HashFunc() {
	case crypto.SHA256:
		algorithm = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
	case crypto.SHA384:
		algorithm = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
	case crypto.SHA512:
		algorithm = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	digestData := bytesToCFData(digest)
	defer C.CFRelease(C.CFTypeRef(digestData))

	var cfError C.CFErrorRef
	signature := C.SecKeyCreateSignature(s.keyRef, algorithm, digestData, &cfError)
	if signature == nilCFDataRef {
		return nil, fmt.Errorf("SecKeyCreateSignature failed")
	}
	defer C.CFRelease(C.CFTypeRef(signature))

	return bytesFromCFData(signature), nil
}

// populateCTKIdentityFromAttrs fills in CTKIdentity fields from a dictionary of attributes.
// It only sets fields that are not already set, allowing merging from multiple sources.
func populateCTKIdentityFromAttrs(identity *CTKIdentity, attrs map[C.CFTypeRef]C.CFTypeRef) {
	if identity.Label == "" {
		if label, ok := getStringAttr(attrs, C.kSecAttrLabel); ok {
			identity.Label = label
		}
	}
	if identity.TokenID == "" {
		if tokenID, ok := getStringAttr(attrs, C.kSecAttrTokenID); ok {
			identity.TokenID = tokenID
		}
	}
	if identity.PublicKeyHash == nil {
		if appLabel, ok := getDataAttr(attrs, C.kSecAttrApplicationLabel); ok {
			identity.PublicKeyHash = appLabel
		}
	}
	if identity.KeySizeInBits == 0 {
		if keySizeInBits, ok := getIntAttr(attrs, C.kSecAttrKeySizeInBits); ok {
			identity.KeySizeInBits = keySizeInBits
		}
	}
}

// populateFromKeyRef extracts attributes from a SecKeyRef and populates the identity.
func (c *CTKIdentity) populateFromKeyRef() error {
	if c.secKeyRef == nilSecKeyRef {
		return fmt.Errorf("no key ref available")
	}

	attrsRef := C.SecKeyCopyAttributes(c.secKeyRef)
	if attrsRef == nilCFDictionaryRef {
		return fmt.Errorf("failed to copy key attributes")
	}
	defer C.CFRelease(C.CFTypeRef(attrsRef))

	attrs := mapFromCFDictionary(attrsRef)
	populateCTKIdentityFromAttrs(c, attrs)
	return nil
}

func buildKeyQuery(addlAttrs map[C.CFTypeRef]C.CFTypeRef, label string, publicKeyHash []byte) C.CFDictionaryRef {
	query := map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass): C.CFTypeRef(C.kSecClassKey),
	}

	tokenIDRef := stringToCFString(CTKCardTokenID)
	query[C.CFTypeRef(C.kSecAttrTokenID)] = C.CFTypeRef(tokenIDRef)
	defer C.CFRelease(C.CFTypeRef(tokenIDRef))

	if label != "" {
		labelRef := stringToCFString(label)
		query[C.CFTypeRef(C.kSecAttrLabel)] = C.CFTypeRef(labelRef)
		defer C.CFRelease(C.CFTypeRef(labelRef))
	}

	if publicKeyHash != nil {
		hashRef := bytesToCFData(publicKeyHash)
		query[C.CFTypeRef(C.kSecAttrApplicationLabel)] = C.CFTypeRef(hashRef)
		defer C.CFRelease(C.CFTypeRef(hashRef))
	}

	maps.Copy(query, addlAttrs)

	return mapToCFDictionary(query)
}

// extractAttributesFromKeyRef is a helper that extracts attributes from a SecKeyRef
// without retaining it (for temporary use only in listing operations).
// Returns nil if the keyRef is invalid or attributes cannot be extracted.
func extractAttributesFromKeyRef(keyRef C.SecKeyRef) map[C.CFTypeRef]C.CFTypeRef {
	if keyRef == nilSecKeyRef {
		return nil
	}
	attrsRef := C.SecKeyCopyAttributes(keyRef)
	if attrsRef == nilCFDictionaryRef {
		return nil
	}
	defer C.CFRelease(C.CFTypeRef(attrsRef))
	return mapFromCFDictionary(attrsRef)
}

// ListCTKIdentities returns all CTK identities (created with sc_auth create-ctk-identity).
func ListCTKIdentities() ([]CTKIdentity, error) {
	q := buildKeyQuery(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecReturnRef):        C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitAll),
	}, "", nil)
	defer C.CFRelease(C.CFTypeRef(q))

	var r C.CFTypeRef
	status := C.SecItemCopyMatching(q, &r)
	if err := newKeychainError(status); err != nil {
		// No items found is not an error for listing
		if ErrorCode(status) == KeychainErrorCodeItemNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("listing CTK identities: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(r))

	result := goSliceFromCFArray(C.CFArrayRef(r))

	identities := make([]CTKIdentity, len(result))
	for i, item := range result {
		itemDict := mapFromCFDictionary(C.CFDictionaryRef(item))
		populateCTKIdentityFromAttrs(&identities[i], itemDict)

		// Supplement with attributes from the key ref directly (if available)
		if ref, ok := itemDict[C.CFTypeRef(C.kSecValueRef)]; ok {
			if keyAttrs := extractAttributesFromKeyRef(C.SecKeyRef(ref)); keyAttrs != nil {
				populateCTKIdentityFromAttrs(&identities[i], keyAttrs)
			}
		}
	}

	return identities, nil
}

// GetCTKIdentity retrieves a single CTK identity by label or public key hash.
// The returned identity can be used for signing via the Signer() method.
// The caller must call Close() on the returned identity when done.
//
// If querying by label and multiple identities match, an error is returned.
// For precise matching, use the publicKeyHash parameter.
func GetCTKIdentity(label string, publicKeyHash []byte) (*CTKIdentity, error) {
	if label == "" && publicKeyHash == nil {
		return nil, fmt.Errorf("either label or publicKeyHash must be provided")
	}

	// If querying by label, first check that only one matches
	if label != "" && publicKeyHash == nil {
		countQuery := buildKeyQuery(map[C.CFTypeRef]C.CFTypeRef{
			C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
			C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitAll),
		}, label, nil)
		defer C.CFRelease(C.CFTypeRef(countQuery))

		var countResult C.CFTypeRef
		status := C.SecItemCopyMatching(countQuery, &countResult)
		if err := newKeychainError(status); err != nil {
			return nil, fmt.Errorf("getting CTK identity: %w", err)
		}
		defer C.CFRelease(C.CFTypeRef(countResult))

		results := goSliceFromCFArray(C.CFArrayRef(countResult))
		if len(results) > 1 {
			return nil, fmt.Errorf("multiple CTK identities found with label %q; use publicKeyHash for precise matching", label)
		}
	}

	q := buildKeyQuery(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecReturnAttributes): C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecReturnRef):        C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit):       C.CFTypeRef(C.kSecMatchLimitOne),
	}, label, publicKeyHash)
	defer C.CFRelease(C.CFTypeRef(q))

	var r C.CFTypeRef
	status := C.SecItemCopyMatching(q, &r)
	if err := newKeychainError(status); err != nil {
		return nil, fmt.Errorf("getting CTK identity: %w", err)
	}
	defer C.CFRelease(C.CFTypeRef(r))

	result := mapFromCFDictionary(C.CFDictionaryRef(r))

	identity := &CTKIdentity{}
	populateCTKIdentityFromAttrs(identity, result)

	// Extract and retain the SecKeyRef
	if ref, ok := result[C.CFTypeRef(C.kSecValueRef)]; ok {
		identity.secKeyRef = C.SecKeyRef(ref)
		C.CFRetain(C.CFTypeRef(identity.secKeyRef))
		if err := identity.populateFromKeyRef(); err != nil {
			return nil, fmt.Errorf("populating identity from key ref: %w", err)
		}
	}

	return identity, nil
}

// GetCTKIdentityByPublicKeyHashHex is a convenience function that calls GetCTKIdentity
// with a hex-encoded public key hash (as shown by sc_auth list-ctk-identities).
func GetCTKIdentityByPublicKeyHashHex(hashHex string) (*CTKIdentity, error) {
	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex public key hash: %w", err)
	}
	return GetCTKIdentity("", hash)
}
