package oidc

import (
	"strings"

	"golang.org/x/oauth2"
)

const (
	// ScopeOpenID is the base OpenID Connect scope.
	ScopeOpenID = "openid"
	// ScopeProfile requests access to the user's default profile claims, which
	// are: name, family_name, given_name, middle_name, nickname,
	// preferred_username, profile, picture, website.
	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopeProfile = "profile"
	// ScopeEmail requests access to the email and email_verified claims.
	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopeEmail = "email"
	// ScopePhone requests access to the phone_number and phone_number_verified
	// claims. https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopePhone = "phone"
	// ScopeAddress requests access to the address claim.
	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	ScopeAddress = "address"
)

func SetACRValues(acrValues []string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("acr_values", strings.Join(acrValues, " "))
}

func SetNonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}
