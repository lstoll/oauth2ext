package tokencache

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

type cachingTokenSource struct {
	src   oauth2.TokenSource
	cache CredentialCache

	iss       string
	aud       string
	scopes    []string
	acrValues []string

	oauth2Config  *oauth2.Config
	oauth2Context context.Context
}

type TokenSourceOpt func(*cachingTokenSource)

// WithCache uses the passed cache
func WithCache(cc CredentialCache) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.cache = cc
	}
}

// WithScopes keys the cache with the additional scopes. Used where tokens need
// to be differed for different scopes.
func WithScopes(scopes []string) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.scopes = scopes
	}
}

// WithACRValues keys the cache with the ACR values. Used where tokens of
// different ACR values are tracked.
func WithACRValues(acrValues []string) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.acrValues = acrValues
	}
}

// WithRefreshConfig will add a oauth2 configuration to the source. This will be
// used to fetch a new token if the cached token is expired and has a
// RefreshToken. The provided context will be used for all refreshes.
func WithRefreshConfig(ctx context.Context, cfg oauth2.Config) TokenSourceOpt {
	return func(c *cachingTokenSource) {
		c.oauth2Context = ctx
		c.oauth2Config = &cfg
	}
}

// TokenSource wraps an oauth2.TokenSource, caching the token results locally so
// they survive cross-process execution. The result of BestCredentialCache is
// used for the cache, this can be overridden with the WithCache option. Items
// are stored in the cache keyed by their issuer and audience, WithScopes and
// WithACRValues can be used to further refine the keying where differentiation
// is required on these values.
func TokenSource(src oauth2.TokenSource, issuer, audience string, opts ...TokenSourceOpt) oauth2.TokenSource {
	ts := &cachingTokenSource{
		src: src,
		iss: issuer,
		aud: audience,
	}

	for _, o := range opts {
		o(ts)
	}

	if ts.cache == nil {
		ts.cache = &MemoryWriteThroughCredentialCache{CredentialCache: BestCredentialCache()}
	}

	return ts
}

// Token checks the cache for a token, and if it exists and is valid returns it.
// Otherwise, it will call the upstream Token source and cache the result,
// before returning it.
func (c *cachingTokenSource) Token() (*oauth2.Token, error) {
	token, err := c.cache.Get(c.iss, c.aud, c.scopes, c.acrValues)
	if err != nil {
		return nil, fmt.Errorf("cache get: %v", err)
	}

	var newToken *oauth2.Token
	if token != nil && token.Valid() {
		return token, nil
	} else if token != nil && token.RefreshToken != "" {
		// we have an expired token, try and refresh if we can.
		rts := c.oauth2Config.TokenSource(c.oauth2Context, token)
		t, err := rts.Token()
		// ignore errors here, just let it fail to a new token
		if err == nil {
			newToken = t
		}
	}

	if newToken == nil {
		// if we get here cache and refresh failed, so fetch from upstream
		t, err := c.src.Token()
		if err != nil {
			return nil, fmt.Errorf("fetching new token: %v", err)
		}
		newToken = t
	}

	if err := c.cache.Set(c.iss, c.aud, c.scopes, c.acrValues, newToken); err != nil {
		return nil, fmt.Errorf("updating cache: %v", err)
	}

	return newToken, nil
}
