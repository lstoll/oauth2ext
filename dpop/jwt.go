package dpop

import (
	"encoding/base64"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
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
	if err := protojson.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}
	return &header, nil
}

func hasClaimOfKind(s *structpb.Struct, name string, kind *structpb.Value) bool {
	val, exist := s.GetFields()[name]
	if !exist || kind == nil {
		return false
	}
	var isKind bool
	switch kind.GetKind().(type) {
	case *structpb.Value_StructValue:
		_, isKind = val.GetKind().(*structpb.Value_StructValue)
	case *structpb.Value_NullValue:
		_, isKind = val.GetKind().(*structpb.Value_NullValue)
	case *structpb.Value_BoolValue:
		_, isKind = val.GetKind().(*structpb.Value_BoolValue)
	case *structpb.Value_ListValue:
		_, isKind = val.GetKind().(*structpb.Value_ListValue)
	case *structpb.Value_StringValue:
		_, isKind = val.GetKind().(*structpb.Value_StringValue)
	case *structpb.Value_NumberValue:
		_, isKind = val.GetKind().(*structpb.Value_NumberValue)
	default:
		isKind = false

	}
	return isKind
}
