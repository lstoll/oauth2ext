package jwt

import (
	"encoding/json/jsontext"
	"fmt"
	"math"
	"time"
)

// VerifiedJWT is an opaque JWT that has passed signature and policy validation.
// The zero value is invalid; obtain instances only via KeySet.VerifyJWT.
type VerifiedJWT struct {
	payload jsontext.Value
	claims  map[string]any
	alg     Algorithm
}

// Algorithm returns the verified JWS signing algorithm.
func (v *VerifiedJWT) Algorithm() (Algorithm, error) {
	if v == nil || v.alg == "" {
		return "", fmt.Errorf("jwt: invalid VerifiedJWT")
	}
	return v.alg, nil
}

func (v *VerifiedJWT) HasIssuer() bool    { return v.HasString("iss") }
func (v *VerifiedJWT) HasSubject() bool   { return v.HasString("sub") }
func (v *VerifiedJWT) HasAudiences() bool { _, err := v.Audiences(); return err == nil }
func (v *VerifiedJWT) HasJWTID() bool     { return v.HasString("jti") }
func (v *VerifiedJWT) HasIssuedAt() bool  { return v.HasNumericDate("iat") }
func (v *VerifiedJWT) HasExpiresAt() bool { return v.HasNumericDate("exp") }
func (v *VerifiedJWT) HasNotBefore() bool { return v.HasNumericDate("nbf") }

func (v *VerifiedJWT) Issuer() (string, error)  { return v.String("iss") }
func (v *VerifiedJWT) Subject() (string, error) { return v.String("sub") }
func (v *VerifiedJWT) JWTID() (string, error)   { return v.String("jti") }
func (v *VerifiedJWT) Audiences() ([]string, error) {
	value, err := v.claim("aud")
	if err != nil {
		return nil, err
	}
	return stringsOrString(value, "aud")
}
func (v *VerifiedJWT) IssuedAt() (time.Time, error)  { return v.NumericDate("iat") }
func (v *VerifiedJWT) ExpiresAt() (time.Time, error) { return v.NumericDate("exp") }
func (v *VerifiedJWT) NotBefore() (time.Time, error) { return v.NumericDate("nbf") }

// Has reports whether claim is present in the verified payload.
func (v *VerifiedJWT) Has(claim string) bool {
	if v == nil || v.claims == nil {
		return false
	}
	_, ok := v.claims[claim]
	return ok
}

// HasString reports whether claim is present and a JSON string.
func (v *VerifiedJWT) HasString(claim string) bool {
	_, err := v.String(claim)
	return err == nil
}

// HasBool reports whether claim is present and a JSON bool.
func (v *VerifiedJWT) HasBool(claim string) bool {
	_, err := v.Bool(claim)
	return err == nil
}

// HasNumber reports whether claim is present and a JSON number.
func (v *VerifiedJWT) HasNumber(claim string) bool {
	_, err := v.Number(claim)
	return err == nil
}

// HasArray reports whether claim is present and a JSON array.
func (v *VerifiedJWT) HasArray(claim string) bool {
	_, err := v.array(claim)
	return err == nil
}

// HasArrayOf reports whether claim is an array whose elements all have type T.
func (v *VerifiedJWT) HasArrayOf[T JSONValue](claim string) bool {
	array, err := v.array(claim)
	if err != nil {
		return false
	}
	for _, element := range array {
		if _, ok := element.(T); !ok {
			return false
		}
	}
	return true
}

// HasObject reports whether claim is present and a JSON object.
func (v *VerifiedJWT) HasObject(claim string) bool {
	value, err := v.claim(claim)
	if err != nil {
		return false
	}
	_, ok := value.(map[string]any)
	return ok
}

// HasNumericDate reports whether claim is present as a valid JWT NumericDate.
func (v *VerifiedJWT) HasNumericDate(claim string) bool {
	_, err := v.NumericDate(claim)
	return err == nil
}

// HasNull reports whether claim is present and JSON null.
func (v *VerifiedJWT) HasNull(claim string) bool {
	if v == nil || v.claims == nil {
		return false
	}
	value, ok := v.claims[claim]
	return ok && value == nil
}

// String returns a string claim.
func (v *VerifiedJWT) String(claim string) (string, error) {
	value, err := v.claim(claim)
	if err != nil {
		return "", err
	}
	out, ok := value.(string)
	if !ok {
		return "", typeError(claim, "string")
	}
	return out, nil
}

// Bool returns a boolean claim.
func (v *VerifiedJWT) Bool(claim string) (bool, error) {
	value, err := v.claim(claim)
	if err != nil {
		return false, err
	}
	out, ok := value.(bool)
	if !ok {
		return false, typeError(claim, "bool")
	}
	return out, nil
}

// Number returns a numeric claim using Go's standard JSON representation.
func (v *VerifiedJWT) Number(claim string) (float64, error) {
	value, err := v.claim(claim)
	if err != nil {
		return 0, err
	}
	out, ok := value.(float64)
	if !ok {
		return 0, typeError(claim, "number")
	}
	return out, nil
}

// Array returns a deep copy of a JSON array claim.
func (v *VerifiedJWT) Array(claim string) ([]any, error) {
	array, err := v.array(claim)
	if err != nil {
		return nil, err
	}
	return cloneJSON(array).([]any), nil
}

// ArrayOf returns a deep copy of a JSON array whose elements all have type T.
func (v *VerifiedJWT) ArrayOf[T JSONValue](claim string) ([]T, error) {
	array, err := v.array(claim)
	if err != nil {
		return nil, err
	}
	out := make([]T, len(array))
	for i, element := range array {
		value, ok := element.(T)
		if !ok {
			return nil, fmt.Errorf("%w: %s[%d] has an unexpected JSON type", ErrClaim, claim, i)
		}
		out[i] = cloneJSON(value).(T)
	}
	return out, nil
}

// Object returns a deep copy of a JSON object claim.
func (v *VerifiedJWT) Object(claim string) (map[string]any, error) {
	value, err := v.claim(claim)
	if err != nil {
		return nil, err
	}
	out, ok := value.(map[string]any)
	if !ok {
		return nil, typeError(claim, "object")
	}
	return cloneJSON(out).(map[string]any), nil
}

// NumericDate returns a JWT NumericDate claim as a time.Time.
func (v *VerifiedJWT) NumericDate(claim string) (time.Time, error) {
	value, err := v.claim(claim)
	if err != nil {
		return time.Time{}, err
	}
	return numericDate(value, claim)
}

// Payload returns a copy of the verified payload JSON.
func (v *VerifiedJWT) Payload() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("jwt: nil VerifiedJWT")
	}
	if len(v.payload) == 0 {
		return nil, fmt.Errorf("jwt: VerifiedJWT has no payload")
	}
	return append([]byte(nil), v.payload...), nil
}

func (v *VerifiedJWT) claim(claim string) (any, error) {
	if v == nil || v.claims == nil {
		return nil, fmt.Errorf("jwt: invalid VerifiedJWT")
	}
	value, ok := v.claims[claim]
	if !ok {
		return nil, claimErr(claim)
	}
	return value, nil
}

func (v *VerifiedJWT) array(claim string) ([]any, error) {
	value, err := v.claim(claim)
	if err != nil {
		return nil, err
	}
	out, ok := value.([]any)
	if !ok {
		return nil, typeError(claim, "array")
	}
	return out, nil
}

func stringsOrString(value any, claim string) ([]string, error) {
	if single, ok := value.(string); ok {
		return []string{single}, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a string or string array", ErrClaim, claim)
	}
	out := make([]string, len(array))
	for i, element := range array {
		value, ok := element.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s[%d] is not a string", ErrClaim, claim, i)
		}
		out[i] = value
	}
	return out, nil
}

func numericDate(value any, claim string) (time.Time, error) {
	seconds, ok := value.(float64)
	if !ok {
		return time.Time{}, typeError(claim, "number")
	}
	if math.IsNaN(seconds) || seconds < 0 || seconds >= math.Exp2(63) {
		return time.Time{}, fmt.Errorf("%w: %s NumericDate is out of range", ErrClaim, claim)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fraction*float64(time.Second))).UTC(), nil
}

func cloneJSON(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, element := range value {
			out[key] = cloneJSON(element)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, element := range value {
			out[i] = cloneJSON(element)
		}
		return out
	default:
		return value
	}
}

func typeError(claim, want string) error {
	return fmt.Errorf("%w: %s is not a %s", ErrClaim, claim, want)
}

func claimErr(name string) error {
	return fmt.Errorf("%w: %s", ErrClaim, name)
}
