package middleware

import "lds.li/oauth2ext/oidc"

// SessionData contains the data this middleware needs to save/restore across
// requests. This should be stored using a method that does not reveal the
// contents to the end user in any way.
type SessionData struct {
	// Logins tracks state for in-progress logins.
	Logins []SessionDataLogin `json:"logins,omitempty"`
	// Token contains the issued token from a successful authentication flow.
	Token *oidc.TokenWithID `json:"token,omitempty"`
}

// SessionDataLogin tracks state for an in-progress auth flow.
type SessionDataLogin struct {
	// State for an in-progress auth flow.
	State string `json:"oidc_state,omitempty"`
	// PKCEChallenge for the in-progress auth flow
	PKCEChallenge string `json:"pkce_challenge,omitempty"`
	// ReturnTo is where we should navigate to at the end of the flow
	ReturnTo string `json:"oidc_return_to,omitempty"`
	// Expires is when this can be discarded, Unix time.
	Expires int `json:"expires,omitempty"`
}
