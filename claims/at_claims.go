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

// JWTTYPAccessToken is the type header for OAuth2 JWT Access tokens.
//
// https://datatracker.ietf.org/doc/html/rfc9068#name-header
const JWTTYPAccessToken = "at+jwt"

// RawAccessTokenClaims represents the set of JWT claims for an OAuth2 JWT Access
// token.
//
// https://datatracker.ietf.org/doc/html/rfc9068
type RawAccessTokenClaims struct {
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
	// Extra contains any other claims that are not part of the standard set.
	// These claims will be marshalled and unmarshalled from the JWT.
	Extra map[string]any `json:"-"`
}

func (a *RawAccessTokenClaims) MarshalJSON() ([]byte, error) {
	// Get all the json tags from the struct to check for conflicts
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*a)
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

	for k := range a.Extra {
		if _, ok := tags[k]; ok {
			return nil, fmt.Errorf("extra claim %q conflicts with standard claim", k)
		}
	}

	type alias RawAccessTokenClaims
	b, err := json.Marshal(alias(*a)) // use alias to prevent recursion
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	maps.Copy(m, a.Extra)

	return json.Marshal(m)
}

func (a *RawAccessTokenClaims) UnmarshalJSON(b []byte) error {
	type alias RawAccessTokenClaims
	if err := json.Unmarshal(b, (*alias)(a)); err != nil {
		return err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	// Get all the json tags from the struct to know which fields are standard
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*a)
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
	a.Extra = make(map[string]any)
	for k, v := range m {
		if _, ok := tags[k]; !ok {
			a.Extra[k] = v
		}
	}

	return nil
}

func (a *RawAccessTokenClaims) String() string {
	m, err := json.Marshal(a)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", a.Subject, err)
	}

	return string(m)
}

func (a *RawAccessTokenClaims) ToRawJWT() (*jwt.RawJWT, error) {
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
		TypeHeader: th.Ptr(JWTTYPAccessToken),
		Issuer:     th.PtrOrNil(a.Issuer),
		Subject:    th.PtrOrNil(a.Subject),
		ExpiresAt:  exp,
		JWTID:      th.PtrOrNil(a.JWTID),
		IssuedAt:   iat,
	}
	if len(a.Audience) == 1 {
		opts.Audience = th.Ptr(a.Audience[0])
	} else if len(a.Audience) > 1 {
		opts.Audiences = a.Audience
	}

	// Use a temp map to not modify the CustomClaims map directly
	customClaims := make(map[string]any)

	if a.Scope != "" {
		customClaims["scope"] = a.Scope
	}
	if a.ClientID != "" {
		customClaims["client_id"] = a.ClientID
	}
	if a.AuthTime != 0 {
		customClaims["auth_time"] = int(a.AuthTime)
	}
	if a.ACR != "" {
		customClaims["acr"] = a.ACR
	}
	if a.AMR != nil {
		customClaims["amr"] = sliceToAnySlice(a.AMR)
	}
	if a.Groups != nil {
		customClaims["groups"] = sliceToAnySlice(a.Groups)
	}
	if a.Roles != nil {
		customClaims["roles"] = sliceToAnySlice(a.Roles)
	}
	if a.Entitlements != nil {
		customClaims["entitlements"] = sliceToAnySlice(a.Entitlements)
	}
	if len(a.Extra) > 0 {
		for k, v := range a.Extra {
			if _, ok := customClaims[k]; ok {
				return nil, fmt.Errorf("duplicate/reserved claim %s", k)
			}
			customClaims[k] = v
		}
	}
	opts.CustomClaims = customClaims

	raw, err := jwt.NewRawJWT(opts)
	if err != nil {
		return nil, fmt.Errorf("constructing raw JWT from claims: %w", err)
	}

	return raw, err
}

// VerifiedAccessToken is a wrapper around a VerifiedJWT that provides accessors
// for the standard claims in an access token.
type VerifiedAccessToken struct {
	*jwt.VerifiedJWT
}

// NewVerifiedAccessToken creates a new VerifiedAccessToken from a VerifiedJWT.
func NewVerifiedAccessToken(v *jwt.VerifiedJWT) *VerifiedAccessToken {
	return &VerifiedAccessToken{VerifiedJWT: v}
}

// HasClientID returns true if the "client_id" claim is present.
func (v *VerifiedAccessToken) HasClientID() bool {
	return v.HasStringClaim("client_id")
}

// ClientID returns the client_id claim from the access token.
func (v *VerifiedAccessToken) ClientID() (string, error) {
	return v.StringClaim("client_id")
}

// HasAuthTime returns true if the "auth_time" claim is present.
func (v *VerifiedAccessToken) HasAuthTime() bool {
	return v.HasNumberClaim("auth_time")
}

// AuthTime returns the time when the End-User authentication occurred.
func (v *VerifiedAccessToken) AuthTime() (time.Time, error) {
	authTime, err := v.NumberClaim("auth_time")
	if err != nil {
		return time.Time{}, fmt.Errorf("getting auth_time: %w", err)
	}

	return time.Unix(int64(authTime), 0), nil
}

// HasACR returns true if the "acr" claim is present.
func (v *VerifiedAccessToken) HasACR() bool {
	return v.HasStringClaim("acr")
}

// ACR returns the Authentication Context Class Reference.
func (v *VerifiedAccessToken) ACR() (string, error) {
	return v.StringClaim("acr")
}

// HasAMR returns true if the "amr" claim is present.
func (v *VerifiedAccessToken) HasAMR() bool {
	return v.HasArrayClaim("amr")
}

// AMR returns the Authentication Methods References.
func (v *VerifiedAccessToken) AMR() ([]string, error) {
	return v.stringSliceClaim("amr")
}

// HasScope returns true if the "scope" claim is present.
func (v *VerifiedAccessToken) HasScope() bool {
	return v.HasStringClaim("scope")
}

// Scope returns the scope claim from the access token.
func (v *VerifiedAccessToken) Scope() (string, error) {
	return v.StringClaim("scope")
}

// HasGroups returns true if the "groups" claim is present.
func (v *VerifiedAccessToken) HasGroups() bool {
	return v.HasArrayClaim("groups")
}

// Groups returns the groups claim from the access token.
func (v *VerifiedAccessToken) Groups() ([]string, error) {
	return v.stringSliceClaim("groups")
}

// HasRoles returns true if the "roles" claim is present.
func (v *VerifiedAccessToken) HasRoles() bool {
	return v.HasArrayClaim("roles")
}

// Roles returns the roles claim from the access token.
func (v *VerifiedAccessToken) Roles() ([]string, error) {
	return v.stringSliceClaim("roles")
}

// HasEntitlements returns true if the "entitlements" claim is present.
func (v *VerifiedAccessToken) HasEntitlements() bool {
	return v.HasArrayClaim("entitlements")
}

// Entitlements returns the entitlements claim from the access token.
func (v *VerifiedAccessToken) Entitlements() ([]string, error) {
	return v.stringSliceClaim("entitlements")
}

func (v *VerifiedAccessToken) stringSliceClaim(claimName string) ([]string, error) {
	claim, err := v.ArrayClaim(claimName)
	if err != nil {
		return nil, fmt.Errorf("getting %s: %w", claimName, err)
	}

	return anySliceToSlice[string](claim)
}
