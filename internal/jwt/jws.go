package jwt

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// ParsedJWS is a compact JWS with one signature. It is intentionally internal:
// protocol packages must authenticate any token-provided verification key before
// calling Verify.
type ParsedJWS struct {
	signed *jose.JSONWebSignature
	Header jose.Header
}

// ParseCompactJWS parses a compact JWS using the supplied algorithm allowlist.
func ParseCompactJWS(compact string, allowed []jose.SignatureAlgorithm) (*ParsedJWS, error) {
	signed, err := jose.ParseSignedCompact(compact, allowed)
	if err != nil {
		return nil, err
	}
	if len(signed.Signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one signature")
	}
	return &ParsedJWS{signed: signed, Header: signed.Signatures[0].Header}, nil
}

// Verify verifies the JWS signature using key. Callers are responsible for
// obtaining key from a trusted source or enforcing their protocol's key-binding
// rules before calling it.
func (p *ParsedJWS) Verify(key any) ([]byte, error) {
	if p == nil || p.signed == nil {
		return nil, fmt.Errorf("nil parsed JWS")
	}
	return p.signed.Verify(key)
}

// DecodeJSONObject strictly decodes a JSON object and preserves its raw form.
func DecodeJSONObject(payload []byte) (jsontext.Value, map[string]any, error) {
	var claims map[string]any
	if err := jsonv2.Unmarshal(payload, &claims); err != nil {
		return nil, nil, err
	}
	if claims == nil {
		return nil, nil, fmt.Errorf("JWT payload is not an object")
	}
	return jsontext.Value(payload).Clone(), claims, nil
}
