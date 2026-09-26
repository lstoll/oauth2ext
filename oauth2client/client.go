// Package oauth2client defines small capabilities for OAuth 2.0 clients.
package oauth2client

import (
	"context"

	"golang.org/x/oauth2"
)

// AuthorizationCodeClient can start and complete an authorization code flow.
// *oauth2.Config and *clientjwt.Config satisfy this interface.
type AuthorizationCodeClient interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(context.Context, string, ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

// TokenSourceProvider can create a source that refreshes OAuth tokens.
// *oauth2.Config and *clientjwt.Config satisfy this interface.
type TokenSourceProvider interface {
	TokenSource(context.Context, *oauth2.Token) oauth2.TokenSource
}

// Client supports authorization code flows and token refresh.
type Client interface {
	AuthorizationCodeClient
	TokenSourceProvider
}

// ClientType explicitly identifies the OAuth client type. It is independent
// of the client's token endpoint authentication method.
type ClientType uint8

const (
	ClientTypeUnspecified ClientType = iota
	PublicClient
	ConfidentialClient
)

// Valid reports whether t identifies a supported client type.
func (t ClientType) Valid() bool {
	return t == PublicClient || t == ConfidentialClient
}
