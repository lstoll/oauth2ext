package internal

import (
	"encoding/base64"
	"errors"
	"strings"

	josejson "github.com/go-jose/go-jose/v4/json"
)

// ErrMalformedJWT is returned when the JWT does not have the expected format.
var ErrMalformedJWT = errors.New("malformed JWT: expected header.payload.signature")

// InsecureExtractJWTPayload extracts the payload part of a JWT and unmarshals
// it into v. v should be a pointer to the target structure. Returns an error if
// the JWT is malformed or the payload cannot be decoded/unmarshaled. This
// performs no validation for the JWT, so its use should be carefully
// considered.
func InsecureExtractJWTPayload(jwt string, v any) error {
	// JWTs are in the form header.payload.signature
	_, rest, found := strings.Cut(jwt, ".")
	if !found {
		return ErrMalformedJWT
	}
	payload, _, found := strings.Cut(rest, ".")
	if !found {
		return ErrMalformedJWT
	}

	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return err
	}

	if err := josejson.Unmarshal(decoded, v); err != nil {
		return err
	}
	return nil
}
