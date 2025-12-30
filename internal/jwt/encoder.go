// Package jwt provides a JWT signer implementation that supports x5c certificate chain headers.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	"google.golang.org/protobuf/types/known/structpb"
)

var _ jwt.Signer = (*Encoder)(nil)

type Encoder struct {
	KID       string
	Signer    crypto.Signer
	CertChain []*x509.Certificate
}

func (e *Encoder) SignAndEncode(raw *jwt.RawJWT) (string, error) {
	return e.encodeWithHeaders(raw, nil)
}

// encodeWithHeaders encodes a JWT with additional custom headers.
// The additionalHeaders struct will be merged into the standard headers (alg, kid, x5c).
// If a key exists in both, the additionalHeaders value takes precedence.
func (e *Encoder) encodeWithHeaders(raw *jwt.RawJWT, additionalHeaders *structpb.Struct) (string, error) {
	// Get the payload JSON
	payload, err := raw.JSONPayload()
	if err != nil {
		return "", fmt.Errorf("getting JSON payload: %w", err)
	}

	// Determine the algorithm from the signer's public key
	alg, err := e.determineAlgorithm()
	if err != nil {
		return "", fmt.Errorf("determining algorithm: %w", err)
	}

	// Build the header using structpb
	header := &structpb.Struct{
		Fields: make(map[string]*structpb.Value),
	}
	header.Fields["alg"] = structpb.NewStringValue(alg)

	// Extract type header from RawJWT if present
	if raw.HasTypeHeader() {
		typ, err := raw.TypeHeader()
		if err == nil {
			header.Fields["typ"] = structpb.NewStringValue(typ)
		}
	}

	if e.KID != "" {
		header.Fields["kid"] = structpb.NewStringValue(e.KID)
	}

	// Add x5c header if CertChain is provided
	if len(e.CertChain) > 0 {
		x5cValues := make([]*structpb.Value, len(e.CertChain))
		for i, cert := range e.CertChain {
			x5cValues[i] = structpb.NewStringValue(base64.StdEncoding.EncodeToString(cert.Raw))
		}
		header.Fields["x5c"] = structpb.NewListValue(&structpb.ListValue{Values: x5cValues})
	}

	// Merge additional headers (they take precedence over everything, including type header from RawJWT)
	if additionalHeaders != nil {
		for k, v := range additionalHeaders.Fields {
			header.Fields[k] = v
		}
	}

	// Encode header and payload
	headerJSON, err := header.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("encoding header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	// Create the signing input: header.payload
	signingInput := headerB64 + "." + payloadB64

	// Sign the data
	hasher, hashOpts, err := e.getHasher(alg)
	if err != nil {
		return "", fmt.Errorf("getting hasher: %w", err)
	}

	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	signature, err := e.Signer.Sign(rand.Reader, hashed, hashOpts)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	if ecdsaKey, ok := e.Signer.Public().(*ecdsa.PublicKey); ok {
		// JWT uses IEEE P1363 format for ECDSA signatures but we have a ASN1
		// DER, convert it.
		tsig, err := subtle.DecodeECDSASignature(signature, "DER")
		if err != nil {
			return "", fmt.Errorf("decoding ECDSA signature: %w", err)
		}
		jwtsig, err := tsig.EncodeECDSASignature("IEEE_P1363", ecdsaKey.Curve.Params().Name)
		if err != nil {
			return "", fmt.Errorf("encoding ECDSA signature: %w", err)
		}
		signature = jwtsig
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return the compact JWT: header.payload.signature
	return signingInput + "." + signatureB64, nil
}

func (e *Encoder) determineAlgorithm() (string, error) {
	pubKey := e.Signer.Public()

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// Determine key size to choose algorithm
		keySize := key.N.BitLen()
		switch {
		case keySize <= 2048:
			return "RS256", nil
		case keySize <= 3072:
			return "RS256", nil
		default:
			return "RS256", nil
		}
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

func (e *Encoder) getHasher(alg string) (hash.Hash, crypto.SignerOpts, error) {
	switch alg {
	case "RS256", "ES256":
		return sha256.New(), crypto.SHA256, nil
	case "RS384", "ES384":
		return sha512.New384(), crypto.SHA384, nil
	case "RS512", "ES512":
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// publicKeyToJWK creates a JWK representation of a public key for use in DPoP tokens.
// It uses Tink to convert the public key to a JWK set and extracts the first key.
// It returns a structpb.Struct that can be used as the "jwk" header value.
func publicKeyToJWK(pubKey crypto.PublicKey) (*structpb.Struct, error) {
	// Determine algorithm from key type
	alg, err := determineAlgorithmFromKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("determining algorithm: %w", err)
	}

	// Create a header with the algorithm for keyset creation
	header := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"alg": structpb.NewStringValue(alg),
		},
	}

	// Create keyset handle from public key using Tink
	// Note: createKeysetHandleFromPublicKey creates a handle with public keys
	handle, err := createKeysetHandleFromPublicKey(pubKey, header)
	if err != nil {
		return nil, fmt.Errorf("creating keyset handle: %w", err)
	}

	// Get the public keyset handle
	// If the handle was created from public keys, we need to get the public version
	// However, if it fails because it's already public, we can try using it directly
	pubHandle, err := handle.Public()
	if err != nil {
		// The handle might already be public-only, so we can use it directly
		// Try to use the handle as-is (it should work if it's already public)
		pubHandle = handle
	}

	// Convert to JWK set
	jwkSetJSON, err := jwt.JWKSetFromPublicKeysetHandle(pubHandle)
	if err != nil {
		return nil, fmt.Errorf("converting to JWK set: %w", err)
	}

	// Parse JWK set using structpb
	var jwkSet structpb.Struct
	if err := jwkSet.UnmarshalJSON(jwkSetJSON); err != nil {
		return nil, fmt.Errorf("parsing JWK set: %w", err)
	}

	// Extract the keys array
	keysVal, ok := jwkSet.Fields["keys"]
	if !ok {
		return nil, fmt.Errorf("JWK set missing 'keys' field")
	}
	if _, ok := keysVal.Kind.(*structpb.Value_ListValue); !ok {
		return nil, fmt.Errorf("JWK set 'keys' field is not a list")
	}
	keysList := keysVal.GetListValue()
	if keysList == nil || len(keysList.Values) == 0 {
		return nil, fmt.Errorf("JWK set is empty")
	}

	// Extract the first JWK
	firstKeyVal := keysList.Values[0]
	if _, ok := firstKeyVal.Kind.(*structpb.Value_StructValue); !ok {
		return nil, fmt.Errorf("first JWK is not a struct")
	}
	jwk := firstKeyVal.GetStructValue()
	if jwk == nil {
		return nil, fmt.Errorf("first JWK is not a struct")
	}

	// Remove alg if present, as it's not part of the jwk header per RFC 9449
	if _, hasAlg := jwk.Fields["alg"]; hasAlg {
		// Create a copy without alg
		jwkWithoutAlg := &structpb.Struct{
			Fields: make(map[string]*structpb.Value, len(jwk.Fields)-1),
		}
		for k, v := range jwk.Fields {
			if k != "alg" {
				jwkWithoutAlg.Fields[k] = v
			}
		}
		jwk = jwkWithoutAlg
	}

	return jwk, nil
}
