package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtecdsa"
	"github.com/tink-crypto/tink-go/v2/jwt/jwtrsassapkcs1"
	"github.com/tink-crypto/tink-go/v2/key"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// publicKeyToJWK creates a JWK representation of a public key for use in DPoP tokens.
// It uses Tink to convert the public key to a JWK set and extracts the first key.
// It returns a map that can be used as the "jwk" header value.
func publicKeyToJWK(pubKey crypto.PublicKey) (map[string]any, error) {
	alg, err := determineAlgorithmFromKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("determining algorithm: %w", err)
	}

	header := map[string]any{
		"alg": alg,
	}

	handle, err := createKeysetHandleFromPublicKey(pubKey, header)
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	jwkSetJSON, err := jwt.JWKSetFromPublicKeysetHandle(handle)
	if err != nil {
		return nil, fmt.Errorf("converting to JWK set: %w", err)
	}

	var jwkSet struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwkSetJSON, &jwkSet); err != nil {
		return nil, fmt.Errorf("parsing JWK set: %w", err)
	}

	if len(jwkSet.Keys) == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	jwk := jwkSet.Keys[0]
	// remove alg if present, as it's not part of the jwk header per RFC 9449
	delete(jwk, "alg")

	return jwk, nil
}

// determineAlgorithmFromKey determines the JWT algorithm from a public key type.
func determineAlgorithmFromKey(pubKey any) (string, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// Default to RS256 for RSA keys TODO - do we want to support other
		// algs? Would need it to be an opt somewhere.
		return "RS256", nil
	case *ecdsa.PublicKey:
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

// createKeysetHandleFromPublicKey creates a tink keyset handle from a public key.
// If header["alg"] is missing, the algorithm is determined from the key type.
func createKeysetHandleFromPublicKey(pubKey any, header map[string]any) (*keyset.Handle, error) {
	var alg string
	var ok bool
	if header != nil {
		alg, ok = header["alg"].(string)
	}
	if !ok {
		// Determine algorithm from key type
		var err error
		alg, err = determineAlgorithmFromKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("missing alg in header and could not determine from key: %w", err)
		}
	}

	manager := keyset.NewManager()

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

	keyID, err := manager.AddKey(tinkKey)
	if err != nil {
		return nil, fmt.Errorf("adding key to manager: %w", err)
	}

	// Set the key as primary, the handle needs one.
	if err := manager.SetPrimary(keyID); err != nil {
		return nil, fmt.Errorf("setting primary key: %w", err)
	}

	handle, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("getting handle from manager: %w", err)
	}

	return handle, nil
}

// createECDSAPublicKey creates a jwtecdsa.PublicKey from an ECDSA public key.
func createECDSAPublicKey(pubKey *ecdsa.PublicKey, alg string) (*jwtecdsa.PublicKey, error) {
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

	params, err := jwtecdsa.NewParameters(jwtecdsa.IgnoredKID, algorithm)
	if err != nil {
		return nil, fmt.Errorf("creating parameters: %w", err)
	}

	publicPoint, err := pubKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("getting public key bytes: %w", err)
	}

	return jwtecdsa.NewPublicKey(jwtecdsa.PublicKeyOpts{
		PublicPoint: publicPoint,
		Parameters:  params,
	})
}

// createRSAPublicKey creates a jwtrsassapkcs1.PublicKey from an RSA public key.
func createRSAPublicKey(pubKey *rsa.PublicKey, alg string) (*jwtrsassapkcs1.PublicKey, error) {
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

	return jwtrsassapkcs1.NewPublicKey(jwtrsassapkcs1.PublicKeyOpts{
		Modulus:    pubKey.N.Bytes(),
		Parameters: params,
	})
}

// canonicalizeJWK creates a canonical JSON representation of a JWK per RFC 7638.
// Keys are sorted alphabetically with no whitespace.
func canonicalizeJWK(jwk map[string]any) ([]byte, error) {
	kty, ok := jwk["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing required member: kty")
	}

	var requiredKeys []string
	canonicalMap := make(map[string]any)

	canonicalMap["kty"] = kty

	switch kty {
	case "EC":
		// EC keys require: kty, crv, x, y
		crv, ok := jwk["crv"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: crv")
		}
		x, ok := jwk["x"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: x")
		}
		y, ok := jwk["y"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for EC key: y")
		}
		canonicalMap["crv"] = crv
		canonicalMap["x"] = x
		canonicalMap["y"] = y
		requiredKeys = []string{"crv", "kty", "x", "y"}

	case "RSA":
		// RSA keys require: kty, n, e
		n, ok := jwk["n"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: n")
		}
		e, ok := jwk["e"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for RSA key: e")
		}
		canonicalMap["e"] = e
		canonicalMap["n"] = n
		requiredKeys = []string{"e", "kty", "n"}

	case "OKP":
		// OKP (Octet Key Pair) keys require: kty, crv, x
		crv, ok := jwk["crv"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: crv")
		}
		x, ok := jwk["x"].(string)
		if !ok {
			return nil, fmt.Errorf("missing required member for OKP key: x")
		}
		canonicalMap["crv"] = crv
		canonicalMap["x"] = x
		requiredKeys = []string{"crv", "kty", "x"}

	default:
		return nil, fmt.Errorf("unsupported key type for thumbprint: %s", kty)
	}

	// Sort keys lexicographically (RFC 7638)
	sort.Strings(requiredKeys)

	// Build canonical JSON with no whitespace
	var parts []string
	for _, k := range requiredKeys {
		v := canonicalMap[k]
		valStr, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected non-string value for key %s", k)
		}
		// JSON encode both key and value
		valJSON, err := json.Marshal(valStr)
		if err != nil {
			return nil, fmt.Errorf("marshaling value for key %s: %w", k, err)
		}
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("marshaling key %s: %w", k, err)
		}
		parts = append(parts, string(keyJSON)+":"+string(valJSON))
	}

	canonicalJSON := "{" + strings.Join(parts, ",") + "}"

	return []byte(canonicalJSON), nil
}

// calculateJWKThumbprint calculates the JWK thumbprint per RFC 7638.
// Returns the base64url-encoded SHA-256 hash of the canonical JWK.
func calculateJWKThumbprint(jwk any) (string, error) {
	jwkMap, ok := jwk.(map[string]any)
	if !ok {
		return "", fmt.Errorf("jwk is not a map")
	}

	canonical, err := canonicalizeJWK(jwkMap)
	if err != nil {
		return "", fmt.Errorf("canonicalizing JWK: %w", err)
	}

	hash := sha256.Sum256(canonical)

	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
