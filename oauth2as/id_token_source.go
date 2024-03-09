package oidc

import (
	"fmt"

	"golang.org/x/oauth2"
)

type idTokenSource struct {
	wrapped oauth2.TokenSource
}

// NewIDTokenSource wraps a token source, re-writing the ID token as the access
// token for outgoing requests. This is a backwards compatibility option for
// services that expect the ID token contents, or where the access token is not
// a JWT/not otherwise verifiable. It should be the _last_ token source in any
// chain, the result from the should not be cached.
//
// Deprecated: Services should expect oauth2 access tokens, and use the userinfo
// endpoint if profile information is required.
func NewIDTokenSource(ts oauth2.TokenSource) oauth2.TokenSource {
	return &idTokenSource{}
}

func (i *idTokenSource) Token() (*oauth2.Token, error) {
	t, err := i.wrapped.Token()
	if err != nil {
		return nil, fmt.Errorf("getting token from wrapped source: %w", err)
	}
	idt, ok := t.Extra("id_token").(string)
	if ok {
		return nil, fmt.Errorf("token contains no id_token")
	}
	newToken := new(oauth2.Token)
	*newToken = *t
	newToken.AccessToken = idt
	return newToken, nil
}
