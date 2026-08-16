package provider

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"mime"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwt/remotejwks"
)

const DefaultCacheDuration = 10 * time.Minute

type Provider struct {
	// Metadata is the discovery metadata for the provider. It will be of type
	// [*OIDCProviderMetadata].
	Metadata      Metadata
	HTTPClient    *http.Client
	CacheDuration time.Duration
	// VerificationKeys overrides keys advertised by discovery. Callers keep
	// this stable handle and replace it when their own refresh routine reloads.
	VerificationKeys *jwt.VerificationKeySet

	refreshMu        sync.Mutex
	cacheMu          sync.RWMutex
	cacheLastFetched time.Time
	keys             *jwt.VerificationKeySet
	keyRefresher     *remotejwks.Source

	oidcDiscoveryURL string
	discoveryIssuer  string
}

func (p *Provider) Issuer() string {
	md, _ := p.snapshot()
	if md == nil {
		return ""
	}
	return md.issuer()
}

// Endpoint returns the OAuth2 endpoint configuration for this provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	md, _ := p.snapshot()
	if md == nil {
		return oauth2.Endpoint{}
	}
	return oauth2.Endpoint{
		AuthURL:  md.authorizationEndpoint(),
		TokenURL: md.tokenEndpoint(),
	}
}

// CodeChallengeMethodsSupported returns the list of PKCE code challenge methods
// supported by this provider. If PKCE is not supported, an empty slice is
// returned.
func (p *Provider) CodeChallengeMethodsSupported() []CodeChallengeMethod {
	md, _ := p.snapshot()
	if md == nil {
		return nil
	}
	return append([]CodeChallengeMethod(nil), md.codeChallengeMethodsSupported()...)
}

// RegistrationSupported returns true if the provider supports client
// registration.
func (p *Provider) RegistrationSupported() bool {
	md, _ := p.snapshot()
	return md != nil && md.registrationSupported()
}

// RegistrationEndpoint returns the registration endpoint for this provider. If
// registration is not supported, an empty string is returned.
func (p *Provider) RegistrationEndpoint() string {
	md, _ := p.snapshot()
	if md == nil {
		return ""
	}
	return md.registrationEndpoint()
}

// IDTokenSigningAlgorithms returns the supported ID token signing algorithms
// that this package can verify.
func (p *Provider) IDTokenSigningAlgorithms(ctx context.Context) ([]jwt.Algorithm, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	md, _ := p.snapshot()
	if md == nil {
		return nil, fmt.Errorf("provider metadata is required")
	}
	return algorithmsFromMetadata(md.idTokenSigningAlgValuesSupported()), nil
}

// JWKS returns the raw JWKS for this provider.
func (p *Provider) JWKS(ctx context.Context) ([]byte, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	_, keys := p.snapshot()
	if keys == nil {
		return nil, fmt.Errorf("provider has no verification keys")
	}
	encoded, err := jsonv2.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("marshalling provider verification keys: %w", err)
	}
	return encoded, nil
}

// VerifyJWT verifies a compact JWT against the provider JWKS and policy.
func (p *Provider) VerifyJWT(ctx context.Context, compact string, policy jwt.ValidationPolicy) (*jwt.VerifiedJWT, error) {
	if len(policy.AllowedAlgorithms) == 0 {
		return nil, fmt.Errorf("JWT policy must specify allowed signing algorithms")
	}
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	md, keys := p.snapshot()
	if md == nil || keys == nil {
		return nil, fmt.Errorf("provider has no verification keys")
	}
	policy.ExpectedIssuer = md.issuer()
	policy.IgnoreIssuer = false
	return keys.VerifyJWT(compact, policy)
}

func algorithmsFromMetadata(algs []string) []jwt.Algorithm {
	out := make([]jwt.Algorithm, 0, len(algs))
	for _, value := range algs {
		alg := jwt.Algorithm(value)
		switch alg {
		case jwt.RS256, jwt.RS384, jwt.RS512,
			jwt.PS256, jwt.PS384, jwt.PS512,
			jwt.ES256, jwt.ES384, jwt.ES512,
			jwt.EdDSA:
			out = append(out, alg)
		}
	}
	return out
}

func (p *Provider) snapshot() (Metadata, *jwt.VerificationKeySet) {
	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()
	return p.Metadata, p.keySetLocked()
}

func (p *Provider) keySetLocked() *jwt.VerificationKeySet {
	if p.VerificationKeys != nil {
		return p.VerificationKeys
	}
	return p.keys
}

// Userinfo will use the token source to query the userinfo endpoint of the
// provider. It will unmarshal the response in to the provided into.
func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource, into any) error {
	md, _ := p.snapshot()
	if md == nil || md.userinfoEndpoint() == "" {
		return fmt.Errorf("provider does not support userinfo endpoint")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, internal.HTTPClientFromContext(ctx, p.HTTPClient))

	client := oauth2.NewClient(ctx, tokenSource)
	res, err := client.Get(md.userinfoEndpoint())
	if err != nil {
		return fmt.Errorf("getting userinfo: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo request failed with code %d", res.StatusCode)
	}

	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("userinfo response has unexpected content type: %s", res.Header.Get("Content-Type"))
	}

	body, err := readBounded(res.Body, maxProviderResponseBytes)
	if err != nil {
		return fmt.Errorf("reading userinfo response: %w", err)
	}

	if err := jsonv2.Unmarshal(body, into); err != nil {
		return fmt.Errorf("unmarshalling userinfo response: %w", err)
	}

	return nil
}
