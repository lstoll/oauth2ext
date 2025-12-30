// Package jwt provides shared utilities for JWT verification.
package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"google.golang.org/protobuf/types/known/structpb"
)

const tokenDelim = "."

// parseToken parses a JWT token string into its three parts: header, claims, and signature.
// Returns ok=false if the token format is invalid (must have exactly 2 periods).
func parseToken(s string) (header, claims, sig string, ok bool) {
	header, s, ok = strings.Cut(s, tokenDelim)
	if !ok { // no period found
		return "", "", "", false
	}
	claims, s, ok = strings.Cut(s, tokenDelim)
	if !ok { // only one period found
		return "", "", "", false
	}
	sig, _, ok = strings.Cut(s, tokenDelim)
	if ok { // three periods found (more than expected)
		return "", "", "", false
	}
	return header, claims, sig, true
}

// parseJWTHeader extracts and parses the JWT header from a compact JWT string.
func parseJWTHeader(compact string) (*structpb.Struct, error) {
	headerB64, _, _, ok := parseToken(compact)
	if !ok {
		return nil, fmt.Errorf("malformed JWT: expected format header.payload.signature")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	var header structpb.Struct
	if err := header.UnmarshalJSON(headerJSON); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	return &header, nil
}

// createKeysetHandleFromPublicKey creates a tink keyset handle from a public key using Manager.
// The header should contain the "alg" field, but if it's missing, the algorithm will be
// determined from the key type (for use cases like JWK generation where alg isn't known yet).
func createKeysetHandleFromPublicKey(pubKey any, header *structpb.Struct) (*keyset.Handle, error) {
	// Extract algorithm from header, or determine from key type if not present
	var alg string
	var ok bool
	if header != nil {
		algVal, exists := header.Fields["alg"]
		if exists {
			if _, isString := algVal.Kind.(*structpb.Value_StringValue); isString {
				alg = algVal.GetStringValue()
				ok = alg != ""
			}
		}
	}
	if !ok {
		// Determine algorithm from key type
		var err error
		alg, err = determineAlgorithmFromKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("missing alg in header and could not determine from key: %w", err)
		}
	}

	// Create a new manager
	manager := keyset.NewManager()

	// Create the appropriate public key based on type
	var tinkKey key.Key
	var err error

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") {
			return nil, fmt.Errorf("algorithm %s does not match RSA key type", alg)
		}
		tinkKey, err = createRSAPublicKey(key, alg)
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return nil, fmt.Errorf("algorithm %s does not match ECDSA key type", alg)
		}
		tinkKey, err = createECDSAPublicKey(key, alg)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	if err != nil {
		return nil, fmt.Errorf("creating tink public key: %w", err)
	}

	// Add the key to the manager
	keyID, err := manager.AddKey(tinkKey)
	if err != nil {
		return nil, fmt.Errorf("adding key to manager: %w", err)
	}

	// Set the key as primary
	if err := manager.SetPrimary(keyID); err != nil {
		return nil, fmt.Errorf("setting primary key: %w", err)
	}

	// Get the handle
	handle, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("getting handle from manager: %w", err)
	}

	return handle, nil
}

// determineAlgorithmFromKey determines the JWT algorithm from a public key type.
// This is similar to Encoder.determineAlgorithm but works on the public key directly.
func determineAlgorithmFromKey(pubKey any) (string, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// Default to RS256 for RSA keys
		return "RS256", nil
	case *ecdsa.PublicKey:
		// Determine curve to choose algorithm
		switch key.Curve.Params().BitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve size: %d", key.Curve.Params().BitSize)
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// createECDSAPublicKey creates a jwtecdsa.PublicKey from an ECDSA public key.
func createECDSAPublicKey(pubKey *ecdsa.PublicKey, alg string) (*jwtecdsa.PublicKey, error) {
	// Determine algorithm
	var algorithm jwtecdsa.Algorithm
	switch alg {
	case "ES256":
		algorithm = jwtecdsa.ES256
		if pubKey.Curve.Params().BitSize != 256 {
			return nil, fmt.Errorf("algorithm ES256 requires P-256 curve, got curve with %d bits", pubKey.Curve.Params().BitSize)
		}
	case "ES384":
		algorithm = jwtecdsa.ES384
		if pubKey.Curve.Params().BitSize != 384 {
			return nil, fmt.Errorf("algorithm ES384 requires P-384 curve, got curve with %d bits", pubKey.Curve.Params().BitSize)
		}
	case "ES512":
		algorithm = jwtecdsa.ES512
		if pubKey.Curve.Params().BitSize != 521 {
			return nil, fmt.Errorf("algorithm ES512 requires P-521 curve, got curve with %d bits", pubKey.Curve.Params().BitSize)
		}
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", alg)
	}

	// Create parameters
	params, err := jwtecdsa.NewParameters(jwtecdsa.IgnoredKID, algorithm)
	if err != nil {
		return nil, fmt.Errorf("creating parameters: %w", err)
	}

	// Get the public key point in uncompressed format (0x04 || x || y)
	publicPoint, err := pubKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("getting public key bytes: %w", err)
	}

	// Create PublicKeyOpts
	opts := jwtecdsa.PublicKeyOpts{
		PublicPoint:   publicPoint,
		IDRequirement: 0,     // Will be assigned by manager
		HasCustomKID:  false, // Not setting custom KID
		Parameters:    params,
	}

	return jwtecdsa.NewPublicKey(opts)
}

// createRSAPublicKey creates a jwtrsassapkcs1.PublicKey from an RSA public key.
func createRSAPublicKey(pubKey *rsa.PublicKey, alg string) (*jwtrsassapkcs1.PublicKey, error) {
	// Determine algorithm
	var algorithm jwtrsassapkcs1.Algorithm
	switch alg {
	case "RS256":
		algorithm = jwtrsassapkcs1.RS256
	case "RS384":
		algorithm = jwtrsassapkcs1.RS384
	case "RS512":
		algorithm = jwtrsassapkcs1.RS512
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	// Create parameters
	paramsOpts := jwtrsassapkcs1.ParametersOpts{
		ModulusSizeInBits: pubKey.N.BitLen(),
		PublicExponent:    pubKey.E,
		KidStrategy:       jwtrsassapkcs1.IgnoredKID,
		Algorithm:         algorithm,
	}
	params, err := jwtrsassapkcs1.NewParameters(paramsOpts)
	if err != nil {
		return nil, fmt.Errorf("creating parameters: %w", err)
	}

	// Encode modulus
	modulus := pubKey.N.Bytes()

	// Create PublicKeyOpts
	opts := jwtrsassapkcs1.PublicKeyOpts{
		Modulus:       modulus,
		IDRequirement: 0,     // Will be assigned by manager
		HasCustomKID:  false, // Not setting custom KID
		Parameters:    params,
	}

	return jwtrsassapkcs1.NewPublicKey(opts)
}
