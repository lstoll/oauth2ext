package tokencache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

var DefaultEarlyExpiry = 30 * time.Second

type Config struct {
	// Issuer is the OIDC issuer, or other unique URL representing the OAuth2
	// authorization server.
	Issuer string
	// CacheKey is used as the key for caching tokens under this issuer. It
	// should uniquely represent the shape of the token issued, to make sure
	// that the correct token is retrieved. e.g it should reflect the client ID,
	// scopes, and any other authentication context used to obtain the token.
	// Helper methods are provided to calculate this. Helpers functions are
	// provided to calculate this. If not provided, the client ID will be used
	// from the Oauth2Config if set. Otherwise, an error will occur.
	CacheKey string
	// WrappedSource is the oauth2.TokenSource we retrieve tokens to cache from.
	WrappedSource oauth2.TokenSource
	// OAuth2Config is the oauth2.Config for the service that tokens are being
	// cached for. If set, this source will attempt to refresh expired tokens.
	OAuth2Config *oauth2.Config
	// Cache to use for caching the retrieved tokens.
	Cache CredentialCache
	// EarlyExpiry is the amount of time before the tokens expiration we will
	// consider it expired, and refresh it. Defaults to DefaultEarlyExpiry, set
	// to a negative value to disable.
	EarlyExpiry time.Duration
}

type oauth2Config interface {
	TokenSource(context.Context, *oauth2.Token) oauth2.TokenSource
}

type cachingTokenSource struct {
	ctx context.Context

	cfg *Config
	// interface for testing
	o2cfg oauth2Config
}

// TokenSource wraps an oauth2.TokenSource, caching the token results locally so
// they survive cross-process execution. If the cached token is expired and a
// refresh token is present, it will attempt to refresh the token before
// retrieving a new one.
func (c *Config) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	var validErr error
	if c.Issuer == "" {
		validErr = errors.Join(validErr, fmt.Errorf("issuer must be specified"))
	}
	if c.CacheKey == "" {
		if c.OAuth2Config == nil || c.OAuth2Config.ClientID == "" {
			validErr = errors.Join(validErr, fmt.Errorf("cache key must be specified when oauth2 config not provided, or it has no client ID"))
		}
		c.CacheKey = c.OAuth2Config.ClientID
	}
	if c.WrappedSource == nil {
		validErr = errors.Join(validErr, fmt.Errorf("a wrapped TokenSource must be provided"))
	}
	if c.Cache == nil {
		validErr = errors.Join(validErr, fmt.Errorf("a cache must be provided"))
	}
	if validErr != nil {
		return nil, fmt.Errorf("invalid config: %w", validErr)
	}
	cs := &cachingTokenSource{ctx: ctx, cfg: c}
	if c.OAuth2Config != nil {
		cs.o2cfg = c.OAuth2Config
	}
	return cs, nil
}

// Token checks the cache for a token, and if it exists and is valid returns it.
// Otherwise, it will call the upstream Token source and cache the result,
// before returning it.
func (c *cachingTokenSource) Token() (*oauth2.Token, error) {
	token, err := c.cfg.Cache.Get(c.cfg.Issuer, c.cfg.CacheKey)
	if err != nil {
		return nil, fmt.Errorf("cache get: %v", err)
	}

	earlyExpiry := c.cfg.EarlyExpiry
	if earlyExpiry == 0 {
		earlyExpiry = DefaultEarlyExpiry
	} else if earlyExpiry < 0 {
		earlyExpiry = 0
	}

	var newToken *oauth2.Token
	if token != nil && token.Valid() && time.Until(token.Expiry) > earlyExpiry {
		return token, nil
	} else if c.o2cfg != nil && token != nil && token.RefreshToken != "" {
		// we have an expired token, try and refresh if we can.
		rts := c.o2cfg.TokenSource(c.ctx, token)
		t, err := rts.Token()
		// ignore errors here, just let it fail to a new token
		if err == nil {
			newToken = t
		}
	}

	if newToken == nil {
		// if we get here cache and refresh failed, so fetch from upstream
		t, err := c.cfg.WrappedSource.Token()
		if err != nil {
			return nil, fmt.Errorf("fetching new token: %v", err)
		}
		newToken = t
	}

	if err := c.cfg.Cache.Set(c.cfg.Issuer, c.cfg.CacheKey, newToken); err != nil {
		return nil, fmt.Errorf("updating cache: %v", err)
	}

	return newToken, nil
}
