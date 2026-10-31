package tokencache

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2client"
)

var DefaultEarlyExpiry = 30 * time.Second

// DPoPTokenSource is a token source that can bind the tokens it obtains to a
// DPoP key. A WrappedSource must implement it when Config.DPoPKeys is set.
// *clitoken's token source implements it.
type DPoPTokenSource interface {
	oauth2.TokenSource
	// DPoPToken obtains a new token bound to signer.
	DPoPToken(signer *jwt.SigningIdentity) (*oauth2.Token, error)
}

type Config struct {
	// Issuer is the OIDC issuer, or other unique URL representing the OAuth2
	// authorization server.
	Issuer string
	// CacheKey is used as the key for caching tokens under this issuer. It
	// should uniquely represent the shape of the token issued, to make sure
	// that the correct token is retrieved. e.g it should reflect the client ID,
	// scopes, and any other authentication context used to obtain the token.
	// Helper methods are provided to calculate this. It is required explicitly;
	// it is never inferred from a concrete OAuth client configuration.
	CacheKey string
	// WrappedSource is the oauth2.TokenSource we retrieve tokens to cache from.
	// It must implement DPoPTokenSource if DPoPKeys is set.
	WrappedSource oauth2.TokenSource
	// TokenSourceProvider creates refresh sources for expired cached tokens.
	// *oauth2.Config and *clientjwt.Config both satisfy this interface.
	TokenSourceProvider oauth2client.TokenSourceProvider
	// Cache to use for caching the retrieved tokens.
	Cache CredentialCache
	// DPoPKeys enables DPoP-bound tokens. A new key is created for each new
	// token from WrappedSource, stored with it in Cache, and used to refresh it.
	// Tokens that the server does not issue as DPoP tokens are rejected. This
	// is usually the same platform Store as Cache, as key handles are only
	// usable with the store that created them.
	DPoPKeys DPoPKeyStore
	// EarlyExpiry is the amount of time before the tokens expiration we will
	// consider it expired, and refresh it. Defaults to DefaultEarlyExpiry, set
	// to a negative value to disable.
	EarlyExpiry time.Duration
}

// TokenSource is a caching token source, created by Config.TokenSource. It is
// safe for concurrent use.
type TokenSource struct {
	ctx context.Context
	cfg *Config

	mu sync.Mutex
	// keyHandle and keySigner hold the most recently used DPoP key, to avoid
	// reloading it for every request.
	keyHandle []byte
	keySigner *jwt.SigningIdentity
}

var _ oauth2.TokenSource = (*TokenSource)(nil)

// TokenSource wraps an oauth2.TokenSource, caching the token results locally so
// they survive cross-process execution. If the cached token is expired and a
// refresh token is present, it will attempt to refresh the token before
// retrieving a new one.
func (c *Config) TokenSource(ctx context.Context) (*TokenSource, error) {
	var validErr error
	if c.Issuer == "" {
		validErr = errors.Join(validErr, fmt.Errorf("issuer must be specified"))
	}
	if c.CacheKey == "" {
		validErr = errors.Join(validErr, fmt.Errorf("cache key must be specified"))
	}
	if c.WrappedSource == nil {
		validErr = errors.Join(validErr, fmt.Errorf("a wrapped TokenSource must be provided"))
	} else if _, ok := c.WrappedSource.(DPoPTokenSource); c.DPoPKeys != nil && !ok {
		validErr = errors.Join(validErr, fmt.Errorf("the wrapped TokenSource must implement DPoPTokenSource when DPoPKeys is set"))
	}
	if c.Cache == nil {
		validErr = errors.Join(validErr, fmt.Errorf("a cache must be provided"))
	}
	if validErr != nil {
		return nil, fmt.Errorf("invalid config: %w", validErr)
	}
	return &TokenSource{ctx: ctx, cfg: c}, nil
}

// Token checks the cache for a token, and if it exists and is valid returns it.
// Otherwise, it will call the upstream Token source and cache the result,
// before returning it. When DPoP is enabled, use DPoPToken or Client to also
// obtain the key the token is bound to.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	tok, _, err := s.DPoPToken()
	return tok, err
}

// DPoPToken returns a token as Token does, along with the DPoP signing identity
// it is bound to. The identity is nil when DPoP is not enabled.
func (s *TokenSource) DPoPToken() (*oauth2.Token, *jwt.SigningIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, err := s.cfg.Cache.Get(s.cfg.Issuer, s.cfg.CacheKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cache get: %v", err)
	}
	// A credential whose binding does not match the configuration can be
	// neither returned nor refreshed, so treat it as a miss.
	if cred != nil && (cred.Token == nil || (s.cfg.DPoPKeys != nil) != (cred.DPoPKey != nil)) {
		cred = nil
	}

	earlyExpiry := s.cfg.EarlyExpiry
	if earlyExpiry == 0 {
		earlyExpiry = DefaultEarlyExpiry
	} else if earlyExpiry < 0 {
		earlyExpiry = 0
	}

	var signer *jwt.SigningIdentity
	if cred != nil && s.cfg.DPoPKeys != nil {
		// A key that can no longer be loaded, e.g. after a hardware reset,
		// means a new login with a new key.
		var loadErr error
		if signer, loadErr = s.loadKey(cred.DPoPKey); loadErr != nil {
			cred, signer = nil, nil
		}
	}

	if cred != nil && cred.Token.Valid() && time.Until(cred.Token.Expiry) > earlyExpiry {
		return cred.Token, signer, nil
	}

	var newCred *Credential
	if cred != nil && s.cfg.TokenSourceProvider != nil && cred.Token.RefreshToken != "" {
		// we have an expired token, try and refresh if we can. A DPoP-bound
		// refresh token must be presented with its key.
		ctx := s.ctx
		if signer != nil {
			ctx = dpop.OAuth2Context(ctx, signer)
		}
		// ignore errors here, just let it fail to a new token
		if t, err := s.cfg.TokenSourceProvider.TokenSource(ctx, cred.Token).Token(); err == nil {
			newCred = &Credential{Token: t, DPoPKey: cred.DPoPKey}
		}
	}

	if newCred == nil {
		// if we get here cache and refresh failed, so fetch from upstream
		newCred = &Credential{}
		var fetchErr error
		if s.cfg.DPoPKeys != nil {
			handle, key, err := s.cfg.DPoPKeys.NewDPoPKey()
			if err != nil {
				return nil, nil, fmt.Errorf("creating DPoP key: %w", err)
			}
			if signer, err = s.setKey(handle, key); err != nil {
				return nil, nil, err
			}
			newCred.DPoPKey = handle
			newCred.Token, fetchErr = s.cfg.WrappedSource.(DPoPTokenSource).DPoPToken(signer)
		} else {
			newCred.Token, fetchErr = s.cfg.WrappedSource.Token()
		}
		if fetchErr != nil {
			return nil, nil, fmt.Errorf("fetching new token: %v", fetchErr)
		}
	}

	if signer != nil && !strings.EqualFold(newCred.Token.TokenType, "DPoP") {
		return nil, nil, fmt.Errorf("DPoP was requested, but the server issued a %q token", newCred.Token.Type())
	}

	if err := s.cfg.Cache.Set(s.cfg.Issuer, s.cfg.CacheKey, newCred); err != nil {
		return nil, nil, fmt.Errorf("updating cache: %v", err)
	}

	return newCred.Token, signer, nil
}

func (s *TokenSource) loadKey(handle []byte) (*jwt.SigningIdentity, error) {
	if s.keySigner != nil && bytes.Equal(s.keyHandle, handle) {
		return s.keySigner, nil
	}
	key, err := s.cfg.DPoPKeys.LoadDPoPKey(handle)
	if err != nil {
		return nil, fmt.Errorf("loading DPoP key: %w", err)
	}
	return s.setKey(handle, key)
}

func (s *TokenSource) setKey(handle []byte, key crypto.Signer) (*jwt.SigningIdentity, error) {
	signer, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		return nil, fmt.Errorf("creating DPoP signing identity: %w", err)
	}
	s.keyHandle, s.keySigner = bytes.Clone(handle), signer
	return signer, nil
}

// Client returns an HTTP client that authorizes requests with this source's
// tokens. When DPoP is enabled, requests use the DPoP scheme and carry a proof
// signed by the token's key. If base is nil, http.DefaultClient is used.
func (s *TokenSource) Client(base *http.Client) *http.Client {
	client := http.Client{}
	if base != nil {
		client = *base
	}
	client.Transport = &transport{source: s, base: client.Transport}
	return &client
}

type transport struct {
	source *TokenSource
	base   http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, signer, err := t.source.DPoPToken()
	if err != nil {
		// RoundTrip must always close the body.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	req = req.Clone(req.Context())
	if signer == nil {
		tok.SetAuthHeader(req)
		return base.RoundTrip(req)
	}
	req.Header.Set("Authorization", "DPoP "+tok.AccessToken)
	return (&dpop.Transport{Signer: signer, Base: base}).RoundTrip(req)
}
