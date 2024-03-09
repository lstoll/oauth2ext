package oidc

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// IDClaims represents the set of JWT claims for a user ID Token.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDClaims
type IDClaims struct {
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

	// Extra are additional claims, that the standard claims will be merged in
	// to. If a key is overridden here, the struct value wins.
	Extra map[string]any `json:"-"`

	// keep the raw data here, so we can unmarshal in to custom structs
	raw json.RawMessage
}

func (c IDClaims) String() string {
	m, err := json.Marshal(&c)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", c.Subject, err)
	}

	return string(m)
}

func (c IDClaims) MarshalJSON() ([]byte, error) {
	// avoid recursing on this method
	type ids IDClaims
	id := ids(c)

	sj, err := json.Marshal(&id)
	if err != nil {
		return nil, err
	}

	sm := map[string]any{}
	if err := json.Unmarshal(sj, &sm); err != nil {
		return nil, err
	}

	om := map[string]any{}

	for k, v := range c.Extra {
		om[k] = v
	}

	for k, v := range sm {
		om[k] = v
	}

	return json.Marshal(om)
}

func (c *IDClaims) UnmarshalJSON(b []byte) error {
	type ids IDClaims
	id := ids{}

	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}

	em := map[string]any{}

	if err := json.Unmarshal(b, &em); err != nil {
		return err
	}

	for _, f := range []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
	} {
		delete(em, f)
	}

	if len(em) > 0 {
		id.Extra = em
	}

	id.raw = b

	*c = IDClaims(id)

	return nil
}

// Unmarshal unpacks the raw JSON data from this token into the passed type.
func (c *IDClaims) Unmarshal(into any) error {
	if c.raw == nil {
		// gracefully handle the weird case where the user might want to call
		// this on a struct of their own creation, rather than one retrieved
		// from a remote source
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		c.raw = b
	}
	return json.Unmarshal(c.raw, into)
}

// StrOrSlice represents a JWT claim that can either be a single string, or a
// list of strings..
type StrOrSlice []string

// Contains returns true if a passed item is found in the set
func (a StrOrSlice) Contains(s string) bool {
	return slices.Contains(a, s)
}

func (a StrOrSlice) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *StrOrSlice) UnmarshalJSON(b []byte) error {
	var ua any
	if err := json.Unmarshal(b, &ua); err != nil {
		return err
	}

	switch ja := ua.(type) {
	case string:
		*a = []string{ja}
	case []any:
		aa := make([]string, len(ja))
		for i, ia := range ja {
			sa, ok := ia.(string)
			if !ok {
				return fmt.Errorf("failed to unmarshal audience, expected []string but found %T", ia)
			}
			aa[i] = sa
		}
		*a = aa
	default:
		return fmt.Errorf("failed to unmarshal audience, expected string or []string but found %T", ua)
	}

	return nil
}

// UnixTime represents the number representing the number of seconds from
// 1970-01-01T0:0:0Z as measured in UTC until the date/time. This is the type
// IDToken uses to represent dates
type UnixTime int64

// NewUnixTime creates a UnixTime from the given Time, t
func NewUnixTime(t time.Time) UnixTime {
	return UnixTime(t.Unix())
}

// Time returns the *time.Time this represents
func (u UnixTime) Time() time.Time {
	return time.Unix(int64(u), 0)
}

func (u UnixTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(u), 10)), nil
}

func (u *UnixTime) UnmarshalJSON(b []byte) error {
	flt, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("failed to parse UnixTime: %v", err)
	}
	*u = UnixTime(int64(flt))
	return nil
}

func claimsFromVerifiedJWT(jwt *jwt.VerifiedJWT) (*IDClaims, error) {
	// TODO(lstoll) is this good enough? Do we want to do more/other processing?
	b, err := jwt.JSONPayload()
	if err != nil {
		return nil, fmt.Errorf("extracting JSON payload: %w", err)
	}
	var cl IDClaims
	if err := json.Unmarshal(b, &cl); err != nil {
		return nil, fmt.Errorf("unmarshaling claims: %w", err)
	}
	return &cl, nil
}

// AccessTokenClaims represents the set of JWT claims for an OAuth2 JWT Access
// token.
//
// https://datatracker.ietf.org/doc/html/rfc9068
type AccessTokenClaims struct {
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
	Expiry UnixTime `json:"exp,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
	Audience StrOrSlice `json:"aud,omitempty"`
	// REQUIRED - as defined in Section 4.1.2 of [RFC7519]. In cases
	// of access tokens obtained through grants where a resource owner is
	// involved, such as the authorization code grant, the value of "sub" SHOULD
	// correspond to the subject identifier of the resource owner. In cases of
	// access tokens obtained through grants where no resource owner is
	// involved, such as the client credentials grant, the value of "sub" SHOULD
	// correspond to an identifier the authorization server uses to indicate the
	// client application. See Section 5 for more details on this scenario.
	// Also, see Section 6 for a discussion about how different choices in
	// assigning "sub" values can impact privacy.
	// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc8693#section-4.3
	ClientID string `json:"client_id,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
	IssuedAt UnixTime `json:"iat,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
	JWTID string `json:"jti,omitempty"`
	// https://www.rfc-editor.org/rfc/rfc8693#section-4.2
	Scope string `json:"scope,omitempty"`
	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	//
	// TODO(lstoll) - do we want to support the more complex than a list version
	// of these, i.e https://www.rfc-editor.org/rfc/rfc7643#section-8.2 ?
	Groups []string `json:"groups,omitempty"`
	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	Roles []string `json:"roles,omitempty"`
	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	Entitlements []string `json:"entitlements,omitempty"`

	// Extra are additional claims, that the standard claims will be merged in
	// to. If a key is overridden here, the struct value wins.
	Extra map[string]any `json:"-"`

	// keep the raw data here, so we can unmarshal in to custom structs
	raw json.RawMessage
}

func (c AccessTokenClaims) MarshalJSON() ([]byte, error) {
	// avoid recursing on this method
	type ids AccessTokenClaims
	id := ids(c)

	sj, err := json.Marshal(&id)
	if err != nil {
		return nil, err
	}

	sm := map[string]any{}
	if err := json.Unmarshal(sj, &sm); err != nil {
		return nil, err
	}

	om := map[string]any{}

	for k, v := range c.Extra {
		om[k] = v
	}

	for k, v := range sm {
		om[k] = v
	}

	return json.Marshal(om)
}

func (c *AccessTokenClaims) UnmarshalJSON(b []byte) error {
	type ids AccessTokenClaims
	id := ids{}

	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}

	em := map[string]any{}

	if err := json.Unmarshal(b, &em); err != nil {
		return err
	}

	for _, f := range []string{
		"iss", "sub", "aud", "exp", "iat", "client_id", "jti", "scope", "groups", "roles", "entitlements",
	} {
		delete(em, f)
	}

	if len(em) > 0 {
		id.Extra = em
	}

	id.raw = b

	*c = AccessTokenClaims(id)

	return nil
}

// Unmarshal unpacks the raw JSON data from this token into the passed type.
func (c *AccessTokenClaims) Unmarshal(into any) error {
	if c.raw == nil {
		// gracefully handle the weird case where the user might want to call
		// this on a struct of their own creation, rather than one retrieved
		// from a remote source
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		c.raw = b
	}
	return json.Unmarshal(c.raw, into)
}
