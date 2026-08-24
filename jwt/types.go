package jwt

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"
)

// JSONValue is a non-null value produced when JSON is decoded into any.
// It constrains ArrayOf and HasArrayOf to ordinary Go JSON representations.
type JSONValue interface {
	string | bool | float64 | []any | map[string]any
}

// NumericDate is a JWT NumericDate represented as a time.Time.
type NumericDate time.Time

// Time returns the NumericDate as a time.Time.
func (n NumericDate) Time() time.Time { return time.Time(n) }

// IsZero reports whether n represents the zero time.
func (n NumericDate) IsZero() bool { return time.Time(n).IsZero() }

// MarshalJSON encodes n as a JWT NumericDate.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, n.Time().Unix(), 10), nil
}

// UnmarshalJSON decodes a JWT NumericDate into n.
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	decoded, err := parseNumericDate(data)
	if err != nil {
		return err
	}
	*n = NumericDate(decoded)
	return nil
}

// Audience represents the recipients for which a JWT is intended.
type Audience []string

// Contains reports whether audience is one of the intended recipients.
func (a Audience) Contains(audience string) bool {
	return slices.Contains(a, audience)
}

// MarshalJSON encodes a using the single-string form when it has one member.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return jsonv2.Marshal(a[0])
	}
	return jsonv2.Marshal([]string(a))
}

// UnmarshalJSON decodes either JWT audience representation into a.
func (a *Audience) UnmarshalJSON(data []byte) error {
	switch jsontext.Value(data).Kind() {
	case jsontext.KindString:
		var audience string
		if err := jsonv2.Unmarshal(data, &audience); err != nil {
			return err
		}
		*a = Audience{audience}
		return nil
	case jsontext.KindBeginArray:
		var audiences []string
		if err := jsonv2.Unmarshal(data, &audiences); err != nil {
			return err
		}
		*a = Audience(audiences)
		return nil
	default:
		return fmt.Errorf("JWT audience must be a JSON string or array of strings")
	}
}

func unmarshalNumericDate(d *jsontext.Decoder) (time.Time, error) {
	token, err := d.ReadToken()
	if err != nil {
		return time.Time{}, err
	}
	if token.Kind() != jsontext.KindNumber {
		return time.Time{}, fmt.Errorf("JWT NumericDate must be a JSON number")
	}

	return parseNumericDate([]byte(token.String()))
}

func parseNumericDate(data []byte) (time.Time, error) {
	seconds, err := strconv.ParseFloat(string(data), 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid JWT NumericDate: %w", err)
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC(), nil
}
