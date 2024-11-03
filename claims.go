package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// https://datatracker.ietf.org/doc/html/rfc9068#name-header
const typJWTAccessToken = "at+jwt"

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

// IDClaims represents the set of JWT claims for a user ID Token, or userinfo
// endpoint.
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
}

func (i *IDClaims) String() string {
	m, err := json.Marshal(i)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", i.Subject, err)
	}

	return string(m)
}

func (i *IDClaims) ToJWT(extraClaims map[string]any) (*jwt.RawJWT, error) {
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
		Issuer:       ptrOrNil(i.Issuer),
		Subject:      ptrOrNil(i.Subject),
		Audiences:    i.Audience,
		ExpiresAt:    exp,
		NotBefore:    nbf,
		IssuedAt:     iat,
		CustomClaims: make(map[string]any),
	}
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
	for k, v := range extraClaims {
		if _, ok := opts.CustomClaims[k]; ok {
			return nil, fmt.Errorf("duplicate/reserved claim %s", k)
		}
		opts.CustomClaims[k] = v
	}

	raw, err := jwt.NewRawJWT(opts)
	if err != nil {
		return nil, fmt.Errorf("constructing raw JWT from claims: %w", err)
	}

	return raw, nil
}

func IDClaimsFromJWT(verified *jwt.VerifiedJWT) (*IDClaims, error) {
	c := new(IDClaims)
	var errs error
	if verified.HasIssuer() {
		v, err := verified.Issuer()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Issuer = v
	}
	if verified.HasSubject() {
		v, err := verified.Subject()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Subject = v
	}
	if verified.HasAudiences() {
		v, err := verified.Audiences()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Audience = StrOrSlice(v)
	}
	if verified.HasExpiration() {
		v, err := verified.ExpiresAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Expiry = UnixTime(v.Unix())
	}
	if verified.HasNotBefore() {
		v, err := verified.NotBefore()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.NotBefore = UnixTime(v.Unix())
	}
	if verified.HasIssuedAt() {
		v, err := verified.IssuedAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.IssuedAt = UnixTime(v.Unix())
	}
	if verified.HasNumberClaim("auth_time") {
		v, err := verified.NumberClaim("auth_time")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AuthTime = UnixTime(v)
	}
	if verified.HasStringClaim("nonce") {
		v, err := verified.StringClaim("nonce")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Nonce = v
	}
	if verified.HasStringClaim("acr") {
		v, err := verified.StringClaim("acr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.ACR = v
	}
	if verified.HasArrayClaim("amr") {
		v, err := verified.ArrayClaim("amr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AMR = sv
	}
	if verified.HasStringClaim("azp") {
		v, err := verified.StringClaim("azp")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AZP = v
	}
	if errs != nil {
		return nil, errs
	}
	return c, nil
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
	// Time when the End-User authentication occurred. Its value is a JSON
	// number representing the number of seconds from 1970-01-01T0:0:0Z as
	// measured in UTC until the date/time. When a max_age request is made or
	// when auth_time is requested as an Essential Claim, then this Claim is
	// REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim
	// semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
	// response parameter.)
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	AuthTime UnixTime `json:"auth_time,omitempty"`
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
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	ACR string `json:"acr,omitempty"`
	// OPTIONAL. Authentication Methods References. JSON array of strings that
	// are identifiers for authentication methods used in the authentication.
	// For instance, values might indicate that both password and OTP
	// authentication methods were used. The definition of particular values to
	// be used in the amr Claim is beyond the scope of this specification.
	// Parties using this claim will need to agree upon the meanings of the
	// values used, which may be context-specific. The amr value is an array of
	// case sensitive strings.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	AMR []string `json:"amr,omitempty"`

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
}

func (a *AccessTokenClaims) String() string {
	m, err := json.Marshal(a)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", a.Subject, err)
	}

	return string(m)
}

func (a *AccessTokenClaims) ToJWT(extraClaims map[string]any) (*jwt.RawJWT, error) {
	var exp *time.Time
	if a.Expiry != 0 {
		t := a.Expiry.Time()
		exp = &t
	}
	var iat *time.Time
	if a.IssuedAt != 0 {
		t := a.IssuedAt.Time()
		iat = &t
	}

	opts := &jwt.RawJWTOptions{
		TypeHeader:   ptr(typJWTAccessToken),
		Issuer:       ptrOrNil(a.Issuer),
		Subject:      ptrOrNil(a.Subject),
		Audiences:    a.Audience,
		ExpiresAt:    exp,
		JWTID:        ptrOrNil(a.JWTID),
		IssuedAt:     iat,
		CustomClaims: make(map[string]any),
	}
	if a.Scope != "" {
		opts.CustomClaims["scope"] = a.Scope
	}
	if a.AuthTime != 0 {
		opts.CustomClaims["auth_time"] = int(a.AuthTime)
	}
	if a.ACR != "" {
		opts.CustomClaims["acr"] = a.ACR
	}
	if a.AMR != nil {
		opts.CustomClaims["amr"] = sliceToAnySlice(a.AMR)
	}
	if a.Groups != nil {
		opts.CustomClaims["groups"] = sliceToAnySlice(a.Groups)
	}
	if a.Groups != nil {
		opts.CustomClaims["roles"] = sliceToAnySlice(a.Roles)
	}
	if a.Entitlements != nil {
		opts.CustomClaims["entitlements"] = sliceToAnySlice(a.Entitlements)
	}
	for k, v := range extraClaims {
		if _, ok := opts.CustomClaims[k]; ok {
			return nil, fmt.Errorf("duplicate/reserved claim %s", k)
		}
		opts.CustomClaims[k] = v
	}

	raw, err := jwt.NewRawJWT(opts)
	if err != nil {
		return nil, fmt.Errorf("constructing raw JWT from claims: %w", err)
	}

	return raw, nil
}

func AccessTokenClaimsFromJWT(verified *jwt.VerifiedJWT) (*AccessTokenClaims, error) {
	c := new(AccessTokenClaims)
	var errs error
	if verified.HasIssuer() {
		v, err := verified.Issuer()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Issuer = v
	}
	if verified.HasSubject() {
		v, err := verified.Subject()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Subject = v
	}
	if verified.HasAudiences() {
		v, err := verified.Audiences()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Audience = StrOrSlice(v)
	}
	if verified.HasExpiration() {
		v, err := verified.ExpiresAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Expiry = UnixTime(v.Unix())
	}
	if verified.HasJWTID() {
		v, err := verified.JWTID()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.JWTID = v
	}
	if verified.HasIssuedAt() {
		v, err := verified.IssuedAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.IssuedAt = UnixTime(v.Unix())
	}
	if verified.HasNumberClaim("auth_time") {
		v, err := verified.NumberClaim("auth_time")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AuthTime = UnixTime(v)
	}
	if verified.HasStringClaim("acr") {
		v, err := verified.StringClaim("acr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.ACR = v
	}
	if verified.HasArrayClaim("amr") {
		v, err := verified.ArrayClaim("amr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AMR = sv
	}
	if verified.HasStringClaim("scope") {
		v, err := verified.StringClaim("scope")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Scope = v
	}
	if verified.HasArrayClaim("groups") {
		v, err := verified.ArrayClaim("groups")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Groups = sv
	}
	if verified.HasArrayClaim("roles") {
		v, err := verified.ArrayClaim("roles")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Groups = sv
	}
	if verified.HasArrayClaim("entitlements") {
		v, err := verified.ArrayClaim("entitlements")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Groups = sv
	}
	if errs != nil {
		return nil, errs
	}
	return c, nil
}

func sliceToAnySlice[T any](v []T) []any {
	r := make([]any, len(v))
	for i, s := range v {
		r[i] = s
	}
	return r
}

func anySliceToSlice[T any](v []any) ([]T, error) {
	r := make([]T, len(v))
	for i, s := range v {
		v, ok := s.(T)
		if !ok {
			return nil, fmt.Errorf("type assert of %#v failed", s)
		}
		r[i] = v
	}
	return r, nil
}

func ptr[T any](v T) *T {
	return &v
}

func ptrOrNil[T comparable](v T) *T {
	var e T
	if v == e {
		return nil
	}
	return &v
}
