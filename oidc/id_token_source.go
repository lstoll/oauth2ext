package oidc

import (
	"fmt"
	"sync"
	"time"

	"github.com/lstoll/oauth2ext/internal"
	"golang.org/x/oauth2"
)

// NewIDTokenSource wraps a token source, re-writing the ID token as the access
// token for outgoing requests. This is a backwards compatibility option for
// services that expect the ID token contents, or where the access token is not
// a JWT/not otherwise verifiable. It should be the _last_ token source in any
// chain, the result from this should not be cached. Provider is optional, if
// provided it will be used to set the token expiry based on the issued token's
// expiry. If nil, the oauth2 token endpoint expiration will be used, which may
// or may not correlate with the ID token's expiration.
//
// Deprecated: Services should expect oauth2 access tokens, and use the userinfo
// endpoint if profile information is required. This will not be removed, but is
// marked as deprecated to require explcit opt-in for linting etc.
func NewIDTokenSource(ts oauth2.TokenSource) oauth2.TokenSource {
	return &idTokenSource{wrapped: ts}
}

type idTokenSource struct {
	mu      sync.Mutex
	wrapped oauth2.TokenSource
}

type expClaims struct {
	Expiry int `json:"exp,omitempty"`
}

func (i *idTokenSource) Token() (*oauth2.Token, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	t, err := i.wrapped.Token()
	if err != nil {
		return nil, fmt.Errorf("getting token from wrapped source: %w", err)
	}
	idt, ok := t.Extra("id_token").(string)
	if !ok || idt == "" {
		return nil, fmt.Errorf("token contains no id_token")
	}
	newToken := new(oauth2.Token)
	*newToken = *t
	newToken.AccessToken = idt

	var expClaims expClaims
	if err := internal.InsecureExtractJWTPayload(idt, &expClaims); err != nil {
		return nil, fmt.Errorf("extracting id token claims: %w", err)
	}
	newToken.Expiry = time.Unix(int64(expClaims.Expiry), 0)
	newToken.ExpiresIn = int64(time.Until(newToken.Expiry).Seconds())
	return newToken, nil
}
