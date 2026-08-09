package dpop

import (
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"
)

const maxProofBytes = 64 << 10

// parseToken parses a compact JWS into its encoded components.
func parseToken(s string) (header, claims, sig string, ok bool) {
	header, s, ok = strings.Cut(s, ".")
	if !ok {
		return "", "", "", false
	}
	claims, s, ok = strings.Cut(s, ".")
	if !ok {
		return "", "", "", false
	}
	if strings.Contains(s, ".") {
		return "", "", "", false
	}
	return header, claims, s, true
}

func decodeJWTPart(encoded, name string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	return decoded, nil
}

// parseJWTHeader strictly decodes the protected header of a compact JWS.
func parseJWTHeader(compact string) (map[string]any, error) {
	if len(compact) > maxProofBytes {
		return nil, fmt.Errorf("DPoP proof exceeds %d bytes", maxProofBytes)
	}
	headerB64, _, _, ok := parseToken(compact)
	if !ok {
		return nil, fmt.Errorf("malformed JWT: expected format header.payload.signature")
	}
	headerJSON, err := decodeJWTPart(headerB64, "header")
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := jsonv2.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}
	if header == nil {
		return nil, fmt.Errorf("JWT header is not an object")
	}
	return header, nil
}
