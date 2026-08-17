package claims

import (
	jsonv2 "encoding/json/v2"
	"fmt"

	"lds.li/oauth2ext/jwt"
)

// RawID is an unverified OpenID Connect ID-token claims set. It is useful for
// constructing tokens and inspecting decoded claims, but its contents must not
// be trusted until the token has been verified.
type RawID struct {
	Issuer    string          `json:"iss,omitzero"`
	Subject   string          `json:"sub,omitzero"`
	Audience  jwt.Audience    `json:"aud,omitzero"`
	ExpiresAt jwt.NumericDate `json:"exp,omitzero"`
	NotBefore jwt.NumericDate `json:"nbf,omitzero"`
	IssuedAt  jwt.NumericDate `json:"iat,omitzero"`
	JWTID     string          `json:"jti,omitzero"`

	Name                string          `json:"name,omitzero"`
	GivenName           string          `json:"given_name,omitzero"`
	FamilyName          string          `json:"family_name,omitzero"`
	MiddleName          string          `json:"middle_name,omitzero"`
	Nickname            string          `json:"nickname,omitzero"`
	PreferredUsername   string          `json:"preferred_username,omitzero"`
	Profile             string          `json:"profile,omitzero"`
	Picture             string          `json:"picture,omitzero"`
	Website             string          `json:"website,omitzero"`
	Email               string          `json:"email,omitzero"`
	EmailVerified       *bool           `json:"email_verified,omitzero"`
	Gender              string          `json:"gender,omitzero"`
	Birthdate           string          `json:"birthdate,omitzero"`
	Zoneinfo            string          `json:"zoneinfo,omitzero"`
	Locale              string          `json:"locale,omitzero"`
	PhoneNumber         string          `json:"phone_number,omitzero"`
	PhoneNumberVerified *bool           `json:"phone_number_verified,omitzero"`
	Address             map[string]any  `json:"address,omitzero"`
	UpdatedAt           jwt.NumericDate `json:"updated_at,omitzero"`

	AuthTime        jwt.NumericDate `json:"auth_time,omitzero"`
	Nonce           string          `json:"nonce,omitzero"`
	ACR             string          `json:"acr,omitzero"`
	AMR             []string        `json:"amr,omitzero"`
	AuthorizedParty string          `json:"azp,omitzero"`
	AtHash          string          `json:"at_hash,omitzero"`
	CHash           string          `json:"c_hash,omitzero"`
	SID             string          `json:"sid,omitzero"`

	// Extra contains custom claims. Standard and typed claims are rejected here.
	Extra map[string]any `json:",embed"`
}

// MarshalJSON marshals r while rejecting typed claims duplicated in Extra.
func (r RawID) MarshalJSON() ([]byte, error) {
	for _, claim := range rawIDClaimNames {
		if _, ok := r.Extra[claim]; ok {
			return nil, fmt.Errorf("claims: Extra contains typed claim %q", claim)
		}
	}
	type rawID RawID
	return jsonv2.Marshal(rawID(r))
}

// UnmarshalJSON unmarshals an unverified ID-token claims set. Duplicate JSON
// object members are rejected and unknown claims are collected in Extra.
func (r *RawID) UnmarshalJSON(data []byte) error {
	type rawID RawID
	var decoded rawID
	if err := jsonv2.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = RawID(decoded)
	return nil
}

var rawIDClaimNames = [...]string{
	"iss", "sub", "aud", "exp", "nbf", "iat", "jti",
	"name", "given_name", "family_name", "middle_name", "nickname",
	"preferred_username", "profile", "picture", "website", "email",
	"email_verified", "gender", "birthdate", "zoneinfo", "locale",
	"phone_number", "phone_number_verified", "address", "updated_at",
	"auth_time", "nonce", "acr", "amr", "azp", "at_hash", "c_hash", "sid",
}
