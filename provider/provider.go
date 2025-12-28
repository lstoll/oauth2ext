package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
)

// jwtTYPAccessToken is the type header for OAuth2 JWT Access tokens.
//
// https://datatracker.ietf.org/doc/html/rfc9068#name-header
const jwtTYPAccessToken = "at+jwt"

const DefaultCacheDuration = 10 * time.Minute

type Provider struct {
	Metadata      Metadata
	HTTPClient    *http.Client
	CacheDuration time.Duration

	cacheMu          sync.Mutex
	cacheLastFetched time.Time
	cachedJWKS       []byte
	cachedHandle     *keyset.Handle

	oidcDiscoveryURL string
}

var _ jwt.Verifier = (*Provider)(nil)

func (p *Provider) Issuer() string {
	return p.Metadata.issuer()
}

// Endpoint returns the OAuth2 endpoint configuration for this provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  p.Metadata.authorizationEndpoint(),
		TokenURL: p.Metadata.tokenEndpoint(),
	}
}

// JWKS returns the raw JWKS for this provider.
func (p *Provider) JWKS(ctx context.Context) ([]byte, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	return p.cachedJWKS, nil
}

// Userinfo will use the token source to query the userinfo endpoint of the
// provider. It will unmarshal the response in to the provided into.
func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource, into any) error {
	if p.Metadata.userinfoEndpoint() == "" {
		return fmt.Errorf("provider does not support userinfo endpoint")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, internal.HTTPClientFromContext(ctx, p.HTTPClient))

	client := oauth2.NewClient(ctx, tokenSource)
	res, err := client.Get(p.Metadata.userinfoEndpoint())
	if err != nil {
		return fmt.Errorf("getting userinfo: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo request failed with code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("userinfo response has unexpected content type: %s", res.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading userinfo response: %w", err)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("unmarshalling userinfo response: %w", err)
	}

	return nil
}

// VerifyAndDecode implements the tink [jwt.Verifier] interface. This provides
// low-level verification of a JWT token against the provider's JWKS. For
// verifying ID or Access tokens, the [lds.li/oauth2ext/claims] package should
// be used.
//
// Note: This method may trigger network calls to refresh the JWKS if needed.
// Using the [Provider.VerifyAndDecodeContext] method is recommended.
func (p *Provider) VerifyAndDecode(compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	return p.VerifyAndDecodeContext(context.Background(), compact, validator)
}

// VerifyAndDecodeContext provides low-level verification of a JWT token against
// the provider's JWKS. For verifying ID or Access tokens, the
// [lds.li/oauth2ext/claims] package should be used. This
func (p *Provider) VerifyAndDecodeContext(ctx context.Context, compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	verif, err := jwt.NewVerifier(p.cachedHandle)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}
	jwt, err := verif.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, err
	}
	// perform an additional check, we should only ever pass tokens from the
	// current issuer.
	iss, err := jwt.Issuer()
	if err != nil {
		return nil, fmt.Errorf("getting issuer: %w", err)
	}
	if iss != p.Metadata.issuer() {
		return nil, fmt.Errorf("invalid issuer: got %q, want %q", iss, p.Metadata.issuer())
	}

	return jwt, nil
}

func ptr[T any](v T) *T {
	return &v
}
