package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
	"github.com/lstoll/oauth2ext/internal"
	"github.com/lstoll/oauth2ext/jwt"
	"golang.org/x/oauth2"
)

const DefaultProviderCacheDuration = 15 * time.Minute

type JWKSFetch func(context.Context) (*jose.JSONWebKeySet, error)

type SigningAlg string

const (
	SigningAlgRS256 SigningAlg = "RS256"
	SigningAlgES256 SigningAlg = "ES256"
)

// Provider represents an OIDC Provider/issuer. It can provide a set of oauth2
// endpoints for the authentication flow, and verify tokens issued by the
// provider against it. It can be constructed via DiscoverProvider
type Provider struct {
	// Metadata for the OIDC provider configuration
	Metadata *ProviderMetadata

	// HTTPClient to use for requests from the provider. If not set, a default
	// will be used. This will be overridden by the context if provided.
	HTTPClient *http.Client

	// Keyset for verifying tokens issued by this provider.
	Keyset jwt.PublicKeyset
}

// DiscoverProvider will discover Provider from the given issuer. The returned
// provider can be modified as needed.
func DiscoverProvider(ctx context.Context, issuer string) (*Provider, error) {
	p := &Provider{
		Metadata:   new(ProviderMetadata),
		HTTPClient: internal.HTTPClientFromContext(ctx, nil),
	}

	cfgURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", cfgURL, err)
	}
	res, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", cfgURL, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status %d from %s, got: %d", http.StatusOK, cfgURL, res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(p.Metadata)
	if err != nil {
		return nil, fmt.Errorf("error decoding provider metadata response: %v", err)
	}

	p.Keyset = &jwt.HTTPJWKSKeyset{
		HTTPClient: p.HTTPClient,
		URL:        p.Metadata.JWKSURI,
	}

	return p, nil
}

// Endpoint returns the OAuth2 endpoint configuration for this provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  p.Metadata.AuthorizationEndpoint,
		TokenURL: p.Metadata.TokenEndpoint,
	}
}

func (p *Provider) GetKeyset() jwt.PublicKeyset {
	return p.Keyset
}

func (p *Provider) GetSupportedAlgs() []string {
	return p.Metadata.IDTokenSigningAlgValuesSupported
}

func (p *Provider) GetIssuer() string {
	return p.Metadata.Issuer
}

func (p *Provider) IDTokenVerifier(clientID string) *jwt.IDTokenVerifier {
	return &jwt.IDTokenVerifier{
		Provider: p,
		ClientID: clientID,
	}
}

// AccessTokenVerifier returns a verifier for access tokens issued by this
// provider, provided they comply with the OAuth2 JWT Access token spec.
func (p *Provider) AccessTokenVerifier() *jwt.AccessTokenVerifier {
	return &jwt.AccessTokenVerifier{
		Provider: p,
	}
}

// Userinfo will use the token source to query the userinfo endpoint of the
// provider. It will unmarshal the response in to the provided into.
func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource, into any) error {
	if p.Metadata.UserinfoEndpoint == "" {
		return fmt.Errorf("provider does not support userinfo endpoint")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, internal.HTTPClientFromContext(ctx, p.HTTPClient))

	client := oauth2.NewClient(ctx, tokenSource)
	res, err := client.Get(p.Metadata.UserinfoEndpoint)
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

	if err := josejson.Unmarshal(body, into); err != nil {
		return fmt.Errorf("unmarshalling userinfo response: %w", err)
	}

	return nil
}
