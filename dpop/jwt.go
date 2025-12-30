package dpop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// parseToken parses a JWT token string into its three parts: header, claims, and signature.
// Returns ok=false if the token format is invalid (must have exactly 2 periods).
func parseToken(s string) (header, claims, sig string, ok bool) {
	header, s, ok = strings.Cut(s, ".")
	if !ok { // no period found
		return "", "", "", false
	}
	claims, s, ok = strings.Cut(s, ".")
	if !ok { // only one period found
		return "", "", "", false
	}
	sig, _, ok = strings.Cut(s, ".")
	if ok { // three periods found (more than expected)
		return "", "", "", false
	}
	return header, claims, sig, true
}

// parseJWTHeader extracts and parses the JWT header from a compact JWT string.
func parseJWTHeader(compact string) (map[string]any, error) {
	headerB64, _, _, ok := parseToken(compact)
	if !ok {
		return nil, fmt.Errorf("malformed JWT: expected format header.payload.signature")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	return header, nil
}
