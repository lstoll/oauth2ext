package jwt

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"time"
)

// JWTMarshalers encodes time.Time values as JWT NumericDates.
var JWTMarshalers = jsonv2.JoinMarshalers(
	jsonv2.MarshalToFunc(func(e *jsontext.Encoder, t time.Time) error {
		return e.WriteToken(jsontext.Int(t.Unix()))
	}),
)

// JWTUnmarshalers decodes JWT NumericDates into time.Time values.
var JWTUnmarshalers = jsonv2.JoinUnmarshalers(
	jsonv2.UnmarshalFromFunc(func(d *jsontext.Decoder, t *time.Time) error {
		decoded, err := unmarshalNumericDate(d)
		if err != nil {
			return err
		}
		*t = decoded
		return nil
	}),
)
