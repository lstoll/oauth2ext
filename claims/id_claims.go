package claims

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"time"

	"github.com/lstoll/oauth2ext/internal/th"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

// RawIDClaims represents the set of JWT claims for a user ID Token, or userinfo
// endpoint.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDClaims
type RawIDClaims struct {
	// REQUIRED. Issuer Identifier for the Issuer of the response. The iss value
	// is a case sensitive URL using the https scheme that contains scheme,
	// host, and optionally, port number and path components and no query or
	// fragment components.
	Issuer string `json:"iss,omitempty"`
	// REQUIRED. Subject Identifier. A locally unique and never reassigned
	// identifier within the Issuer for the End-User, which is intended to be
	// consumed by the Client, e.g., 24400320 or
	// AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII
	// characters in length. The sub value is a case sensitive string.
	Subject string `json:"sub,omitempty"`
	// REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain
	// the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY
	// also contain identifiers for other audiences.
	Audience StrOrSlice `json:"aud,omitempty"`
	// REQUIRED. Expiration time on or after which the ID Token MUST NOT be
	// accepted for processing. The processing of this parameter requires that
	// the current date/time MUST be before the expiration date/time listed in
	// the value. Implementers MAY provide for some small leeway, usually no
	// more than a few minutes, to account for clock skew.
	Expiry UnixTime `json:"exp,omitempty"`
	// OPTIONAL. The "nbf" (not before) claim identifies the time before which
	// the JWT MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to the
	// not-before date/time listed in the "nbf" claim.  Implementers MAY provide
	// for some small leeway, usually no more than a few minutes, to account for
	// clock skew.  Its value MUST be a number containing a NumericDate value.
	NotBefore UnixTime `json:"nbf,omitempty"`
	// REQUIRED. Time at which the JWT was issued.
	IssuedAt UnixTime `json:"iat,omitempty"`
	// Time when the End-User authentication occurred. Its value is a JSON
	// number representing the number of seconds from 1970-01-01T0:0:0Z as
	// measured in UTC until the date/time. When a max_age request is made or
	// when auth_time is requested as an Essential Claim, then this Claim is
	// REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim
	// semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
	// response parameter.)
	AuthTime UnixTime `json:"auth_time,omitempty"`
	// String value used to associate a Client session with an ID Token, and to
	// mitigate replay attacks. The value is passed through unmodified from the
	// Authentication Request to the ID Token. If present in the ID Token,
	// Clients MUST verify that the nonce Claim Value is equal to the value of
	// the nonce parameter sent in the Authentication Request. If present in the
	// Authentication Request, Authorization Servers MUST include a nonce Claim
	// in the ID Token with the Claim Value being the nonce value sent in the
	// Authentication Request. Authorization Servers SHOULD perform no other
	// processing on nonce values used. The nonce value is a case sensitive
	// string.
	Nonce string `json:"nonce,omitempty"`
	// OPTIONAL. Authentication Context Class Reference. String specifying an
	// Authentication Context Class Reference value that identifies the
	// Authentication Context Class that the authentication performed satisfied.
	// The value "0" indicates the End-User authentication did not meet the
	// requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a
	// long-lived browser cookie, for instance, is one example where the use of
	// "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used
	// to authorize access to any resource of any monetary value. (This
	// corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An
	// absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as
	// the acr value; registered names MUST NOT be used with a different meaning
	// than that which is registered. Parties using this claim will need to
	// agree upon the meanings of the values used, which may be
	// context-specific. The acr value is a case sensitive string.
	ACR string `json:"acr,omitempty"`
	// OPTIONAL. Authentication Methods References. JSON array of strings that
	// are identifiers for authentication methods used in the authentication.
	// For instance, values might indicate that both password and OTP
	// authentication methods were used. The definition of particular values to
	// be used in the amr Claim is beyond the scope of this specification.
	// Parties using this claim will need to agree upon the meanings of the
	// values used, which may be context-specific. The amr value is an array of
	// case sensitive strings.
	AMR []string `json:"amr,omitempty"`
	// OPTIONAL. Authorized party - the party to which the ID Token was issued.
	// If present, it MUST contain the OAuth 2.0 Client ID of this party. This
	// Claim is only needed when the ID Token has a single audience value and
	// that audience is different than the authorized party. It MAY be included
	// even when the authorized party is the same as the sole audience. The azp
	// value is a case sensitive string containing a StringOrURI value.
	AZP string `json:"azp,omitempty"`

	// Extra contains any other claims that are not part of the standard set.
	// These claims will be marshalled and unmarshalled from the JWT.
	Extra map[string]any `json:"-"`
}

func (i *RawIDClaims) MarshalJSON() ([]byte, error) {
	// Get all the json tags from the struct to check for conflicts
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*i)
	for j := 0; j < val.NumField(); j++ {
		field := val.Field(j)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			tags[name] = struct{}{}
		}
	}

	for k := range i.Extra {
		if _, ok := tags[k]; ok {
			return nil, fmt.Errorf("extra claim %q conflicts with standard claim", k)
		}
	}

	type alias RawIDClaims
	b, err := json.Marshal(alias(*i)) // use alias to prevent recursion
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	maps.Copy(m, i.Extra)

	return json.Marshal(m)
}

func (i *RawIDClaims) UnmarshalJSON(b []byte) error {
	type alias RawIDClaims
	if err := json.Unmarshal(b, (*alias)(i)); err != nil {
		return err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	// Get all the json tags from the struct to know which fields are standard
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*i)
	for j := 0; j < val.NumField(); j++ {
		field := val.Field(j)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			tags[name] = struct{}{}
		}
	}
	i.Extra = make(map[string]any)
	for k, v := range m {
		if _, ok := tags[k]; !ok {
			i.Extra[k] = v
		}
	}

	return nil
}

func (i *RawIDClaims) String() string {
	m, err := json.Marshal(i)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", i.Subject, err)
	}

	return string(m)
}

func (i *RawIDClaims) ToRawJWT() (*jwt.RawJWT, error) {
	var exp *time.Time
	if i.Expiry != 0 {
		t := i.Expiry.Time()
		exp = &t
	}
	var nbf *time.Time
	if i.NotBefore != 0 {
		t := i.NotBefore.Time()
		nbf = &t
	}
	var iat *time.Time
	if i.IssuedAt != 0 {
		t := i.IssuedAt.Time()
		iat = &t
	}

	opts := &jwt.RawJWTOptions{
		Issuer:    th.PtrOrNil(i.Issuer),
		Subject:   th.PtrOrNil(i.Subject),
		ExpiresAt: exp,
		NotBefore: nbf,
		IssuedAt:  iat,
	}
	if len(i.Audience) == 1 {
		opts.Audience = th.Ptr(i.Audience[0])
	} else if len(i.Audience) > 1 {
		opts.Audiences = i.Audience
	}
	opts.CustomClaims = make(map[string]any)

	if i.AuthTime != 0 {
		opts.CustomClaims["auth_time"] = int(i.AuthTime)
	}
	if i.Nonce != "" {
		opts.CustomClaims["nonce"] = i.Nonce
	}
	if i.ACR != "" {
		opts.CustomClaims["acr"] = i.ACR
	}
	if i.AMR != nil {
		opts.CustomClaims["amr"] = sliceToAnySlice(i.AMR)
	}
	if i.AZP != "" {
		opts.CustomClaims["azp"] = i.AZP
	}
	if len(i.Extra) > 0 {
		for k, v := range i.Extra {
			if _, ok := opts.CustomClaims[k]; ok {
				return nil, fmt.Errorf("duplicate/reserved claim %s", k)
			}
			opts.CustomClaims[k] = v
		}
	}

	raw, err := jwt.NewRawJWT(opts)
	if err != nil {
		return nil, fmt.Errorf("constructing raw JWT from claims: %w", err)
	}

	return raw, err
}

// VerifiedIDClaims is a wrapper around a VerifiedJWT that provides accessors for
// the standard claims in an ID token.
type VerifiedIDClaims struct {
	*jwt.VerifiedJWT
}

// NewVerifiedIDClaims creates a new VerifiedIDClaims from a VerifiedJWT.
func NewVerifiedIDClaims(v *jwt.VerifiedJWT) *VerifiedIDClaims {
	return &VerifiedIDClaims{VerifiedJWT: v}
}

// HasAuthTime returns true if the "auth_time" claim is present.
func (v *VerifiedIDClaims) HasAuthTime() bool {
	return v.HasNumberClaim("auth_time")
}

// AuthTime returns the time when the End-User authentication occurred.
func (v *VerifiedIDClaims) AuthTime() (time.Time, error) {
	authTime, err := v.NumberClaim("auth_time")
	if err != nil {
		return time.Time{}, fmt.Errorf("getting auth_time: %w", err)
	}

	return time.Unix(int64(authTime), 0), nil
}

// HasNonce returns true if the "nonce" claim is present.
func (v *VerifiedIDClaims) HasNonce() bool {
	return v.HasStringClaim("nonce")
}

// Nonce returns the nonce value from the ID token.
func (v *VerifiedIDClaims) Nonce() (string, error) {
	return v.StringClaim("nonce")
}

// HasACR returns true if the "acr" claim is present.
func (v *VerifiedIDClaims) HasACR() bool {
	return v.HasStringClaim("acr")
}

// ACR returns the Authentication Context Class Reference.
func (v *VerifiedIDClaims) ACR() (string, error) {
	return v.StringClaim("acr")
}

// HasAMR returns true if the "amr" claim is present.
func (v *VerifiedIDClaims) HasAMR() bool {
	return v.HasArrayClaim("amr")
}

// AMR returns the Authentication Methods References.
func (v *VerifiedIDClaims) AMR() ([]string, error) {
	claim, err := v.ArrayClaim("amr")
	if err != nil {
		return nil, fmt.Errorf("getting amr: %w", err)
	}

	strs := make([]string, len(claim))
	for i, v := range claim {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("amr claim is not a slice of strings")
		}
		strs[i] = s
	}

	return strs, nil
}

// HasAZP returns true if the "azp" claim is present.
func (v *VerifiedIDClaims) HasAZP() bool {
	return v.HasStringClaim("azp")
}

// AZP returns the Authorized party.
func (v *VerifiedIDClaims) AZP() (string, error) {
	return v.StringClaim("azp")
}
