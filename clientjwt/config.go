package clientjwt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

// Config is an OAuth2 client that authenticates token requests with
// private_key_jwt. It embeds [oauth2.Config], preserving the standard
// authorization-code, PKCE, refresh, and device-flow behavior.
//
// ClientSecret is never sent. Signer and SigningAlgorithm must be configured
// before token requests.
type Config struct {
	oauth2.Config
	Signer           jwt.Signer
	SigningAlgorithm jwt.Algorithm
	// AssertionAudience overrides the default token endpoint audience.
	// Leave empty to use Endpoint.TokenURL.
	AssertionAudience string
	// CertificateThumbprint requests x5t#S256 presentation in assertion headers.
	CertificateThumbprint bool
	HTTPClient            *http.Client
}

// Exchange redeems an authorization code. The standard oauth2 implementation
// performs request construction and response parsing; the transport injects a
// fresh assertion immediately before the token request is sent.
func (c *Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c.oauthConfig().Exchange(c.withHTTPClient(ctx), code, opts...)
}

// TokenSource returns a source that refreshes with a fresh client assertion on
// every token endpoint request.
func (c *Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	if err := c.validate(); err != nil {
		return oauth2.ReuseTokenSource(nil, errorTokenSource{err: err})
	}
	return c.oauthConfig().TokenSource(c.withHTTPClient(ctx), t)
}

// Client returns an HTTP client whose token source uses private_key_jwt.
func (c *Config) Client(ctx context.Context, t *oauth2.Token) *http.Client {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.validate(); err != nil {
		return oauth2.NewClient(ctx, errorTokenSource{err: err})
	}
	ctx = c.withHTTPClient(ctx)
	return oauth2.NewClient(ctx, c.oauthConfig().TokenSource(ctx, t))
}

// PasswordCredentialsToken exchanges resource-owner credentials using a fresh
// client assertion.
func (c *Config) PasswordCredentialsToken(ctx context.Context, username, password string) (*oauth2.Token, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c.oauthConfig().PasswordCredentialsToken(c.withHTTPClient(ctx), username, password)
}

// DeviceAccessToken polls for a device-code token using a fresh assertion on
// every poll.
func (c *Config) DeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c.oauthConfig().DeviceAccessToken(c.withHTTPClient(ctx), da, opts...)
}

func (c *Config) validate() error {
	if c == nil {
		return fmt.Errorf("clientjwt: nil config")
	}
	if c.Signer == nil {
		return fmt.Errorf("clientjwt: signer is required")
	}
	if c.SigningAlgorithm == "" {
		return fmt.Errorf("clientjwt: SigningAlgorithm is required")
	}
	if !c.Signer.SupportsAlgorithm(c.SigningAlgorithm) {
		return fmt.Errorf("clientjwt: signer does not support SigningAlgorithm %s", c.SigningAlgorithm)
	}
	if c.ClientID == "" {
		return fmt.Errorf("clientjwt: ClientID is required")
	}
	if c.Endpoint.TokenURL == "" {
		return fmt.Errorf("clientjwt: Endpoint.TokenURL is required")
	}
	return nil
}

func (c *Config) oauthConfig() *oauth2.Config {
	config := c.Config
	// Authentication is injected by assertionTransport. Emptying the secret
	// prevents x/oauth2 from ever putting a caller-supplied secret on the wire.
	config.ClientSecret = ""
	config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	return &config
}

func (c *Config) withHTTPClient(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	base := c.HTTPClient
	if client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && client != nil {
		base = client
	}
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.Transport = &assertionTransport{
		base:                  base.Transport,
		tokenURL:              c.Endpoint.TokenURL,
		clientID:              c.ClientID,
		signer:                c.Signer,
		algorithm:             c.SigningAlgorithm,
		audience:              c.assertionAudience(),
		certificateThumbprint: c.CertificateThumbprint,
	}
	baseCheckRedirect := base.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		for _, previous := range via {
			if previous.URL.String() == c.Endpoint.TokenURL {
				return http.ErrUseLastResponse
			}
		}
		if baseCheckRedirect != nil {
			return baseCheckRedirect(req, via)
		}
		return nil
	}
	return context.WithValue(ctx, oauth2.HTTPClient, &client)
}

func (c *Config) assertionAudience() string {
	if c.AssertionAudience != "" {
		return c.AssertionAudience
	}
	return c.Endpoint.TokenURL
}

type assertionTransport struct {
	base                  http.RoundTripper
	tokenURL              string
	clientID              string
	signer                jwt.Signer
	algorithm             jwt.Algorithm
	audience              string
	certificateThumbprint bool
}

const maxTokenRequestBody = 1 << 20

func (t *assertionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method != http.MethodPost || req.URL.String() != t.tokenURL {
		return base.RoundTrip(req)
	}
	if req.Body == nil {
		return nil, fmt.Errorf("clientjwt: token request has no body")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxTokenRequestBody+1))
	if err != nil {
		return nil, fmt.Errorf("clientjwt: reading token request: %w", err)
	}
	_ = req.Body.Close()
	if len(body) > maxTokenRequestBody {
		return nil, fmt.Errorf("clientjwt: token request exceeds %d bytes", maxTokenRequestBody)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("clientjwt: parsing token request: %w", err)
	}
	values.Del("client_secret")
	values.Set("client_id", t.clientID)
	assertion, err := Sign(req.Context(), t.signer, SignOptions{
		ClientID:              t.clientID,
		Audience:              t.audience,
		Algorithm:             t.algorithm,
		CertificateThumbprint: t.certificateThumbprint,
	})
	if err != nil {
		return nil, err
	}
	values.Set("client_assertion_type", AssertionType)
	values.Set("client_assertion", assertion)
	encoded := values.Encode()

	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Del("Authorization")
	clone.Body = io.NopCloser(strings.NewReader(encoded))
	clone.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(encoded)), nil }
	clone.ContentLength = int64(len(encoded))
	return base.RoundTrip(clone)
}

type errorTokenSource struct{ err error }

func (s errorTokenSource) Token() (*oauth2.Token, error) { return nil, s.err }
