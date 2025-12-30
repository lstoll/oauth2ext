package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"maps"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/signature/subtle"
	"lds.li/oauth2ext/internal/th"
)

// Signer is used to sign DPoP proofs
type Signer struct {
	signer crypto.Signer
	jwk    map[string]any
}

// NewSigner creates a new Signer using the provided [crypto.Signer].
// The signer should represent a hardware bound or otherwise unextractable
// signing key. The JWK will be calculated from the signer's public key.
func NewSigner(signer crypto.Signer) (*Signer, error) {
	jwk, err := publicKeyToJWK(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %v", err)
	}
	return &Signer{
		signer: signer,
		jwk:    jwk,
	}, nil
}

// SignAndEncode signs the JWT as a DPoP proof, and returns the compact JWT.
func (e *Signer) SignAndEncode(raw *jwt.RawJWTOptions) (string, error) {
	raw.TypeHeader = th.Ptr("dpop+jwt")
	rawJWT, err := jwt.NewRawJWT(raw)
	if err != nil {
		return "", fmt.Errorf("creating raw JWT: %w", err)
	}
	return e.encodeWithHeaders(rawJWT, map[string]any{
		"jwk": e.jwk,
	})
}

// encodeWithHeaders encodes a JWT with additional custom headers. If a key
// exists in both, the additionalHeaders value takes precedence.
func (e *Signer) encodeWithHeaders(raw *jwt.RawJWT, additionalHeaders map[string]any) (string, error) {
	payload, err := raw.JSONPayload()
	if err != nil {
		return "", fmt.Errorf("getting JSON payload: %w", err)
	}

	alg, err := e.determineAlgorithm()
	if err != nil {
		return "", fmt.Errorf("determining algorithm: %w", err)
	}

	header := map[string]any{
		"alg": alg,
	}

	if raw.HasTypeHeader() {
		typ, err := raw.TypeHeader()
		if err == nil {
			header["typ"] = typ
		}
	}

	maps.Copy(header, additionalHeaders)

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encoding header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := headerB64 + "." + payloadB64

	hasher, hashOpts, err := e.getHasher(alg)
	if err != nil {
		return "", fmt.Errorf("getting hasher: %w", err)
	}

	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	signature, err := e.signer.Sign(rand.Reader, hashed, hashOpts)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	if ecdsaKey, ok := e.signer.Public().(*ecdsa.PublicKey); ok {
		// JWT uses IEEE P1363 format for ECDSA signatures but Go returns ASN.1
		// DER format, so convert it.
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

	return signingInput + "." + signatureB64, nil
}

func (e *Signer) determineAlgorithm() (string, error) {
	pubKey := e.signer.Public()

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// TODO - how best to support other algs? Add an opt?
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

func (e *Signer) getHasher(alg string) (hash.Hash, crypto.SignerOpts, error) {
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
