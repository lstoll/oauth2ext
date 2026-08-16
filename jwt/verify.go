package jwt

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const maxTokenBytes = 256 << 10 // 256 KiB

type payloadCapture struct {
	payload jsontext.Value
	claims  map[string]any
}

func (p *payloadCapture) UnmarshalJSON(data []byte) error {
	var claims map[string]any
	if err := jsonv2.Unmarshal(data, &claims); err != nil {
		return err
	}
	if claims == nil {
		return fmt.Errorf("JWT payload is not an object")
	}
	p.payload = jsontext.Value(data).Clone()
	p.claims = claims
	return nil
}

// VerifyJWT verifies a compact JWT and returns an opaque verified token.
func (k *VerificationKeySet) VerifyJWT(compact string, policy ValidationPolicy) (*VerifiedJWT, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil key set", ErrKey)
	}
	if len(compact) > maxTokenBytes {
		return nil, verificationErrorf(VerificationErrorCodeInvalidToken, "token exceeds %d bytes", maxTokenBytes)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}

	allowed, err := toJoseAlgorithms(policy.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}

	tok, err := josejwt.ParseSigned(compact, allowed)
	if err != nil {
		return nil, mapParseError(err)
	}
	if len(tok.Headers) != 1 {
		return nil, verificationErrorf(VerificationErrorCodeInvalidToken, "expected exactly one signature")
	}
	header := tok.Headers[0]
	if err := rejectTokenControlledKeys(header); err != nil {
		return nil, err
	}

	typ, err := typeHeader(header)
	if err != nil {
		return nil, err
	}
	if err := validateType(typ, policy); err != nil {
		return nil, err
	}

	verificationKeys, err := k.matchingKeys(string(header.Algorithm), header.KeyID)
	if err != nil {
		return nil, verificationErrorf(VerificationErrorCodeKey, "%v", err)
	}
	if len(verificationKeys) == 0 {
		return nil, verificationErrorf(VerificationErrorCodeKey, "no key for algorithm %q and kid %q", header.Algorithm, header.KeyID)
	}

	var lastErr error
	for _, key := range verificationKeys {
		var dest payloadCapture
		if err := tok.Claims(key, &dest); err != nil {
			lastErr = err
			continue
		}
		if err := validateClaims(dest.claims, policy, time.Now()); err != nil {
			return nil, err
		}
		return &VerifiedJWT{
			payload: dest.payload,
			claims:  dest.claims,
			alg:     Algorithm(header.Algorithm),
		}, nil
	}
	return nil, mapClaimsError(lastErr)
}

func rejectTokenControlledKeys(header jose.Header) error {
	if header.JSONWebKey != nil {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "token-controlled key sources are not allowed")
	}
	if headerString(header, "jku") != "" || headerString(header, "x5u") != "" {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "token-controlled key sources are not allowed")
	}
	if _, ok := header.ExtraHeaders[jose.HeaderKey("crit")]; ok {
		return verificationErrorf(VerificationErrorCodeInvalidToken, "critical headers are not supported")
	}
	return nil
}

func validateType(typ string, policy ValidationPolicy) error {
	if typ != policy.ExpectedType {
		return verificationErrorf(VerificationErrorCodeType, "typ mismatch: got %q, want %q", typ, policy.ExpectedType)
	}
	return nil
}

func typeHeader(header jose.Header) (string, error) {
	if header.ExtraHeaders == nil {
		return "", nil
	}
	value, ok := header.ExtraHeaders[jose.HeaderType]
	if !ok {
		return "", nil
	}
	typ, ok := value.(string)
	if !ok {
		return "", verificationErrorf(VerificationErrorCodeType, "typ header is not a string")
	}
	return typ, nil
}
