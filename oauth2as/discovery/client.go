package discovery

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
)

// DefaultJWKSCacheDuration defines the default time we cache a JWKS response,
// to avoid excessive requests to the issuer.
const DefaultJWKSCacheDuration = 15 * time.Minute

const oidcwk = "/.well-known/openid-configuration"

// keep us looking like a keysource, for consistency
var _ PublicKeysetHandleFunc = ((*Client)(nil)).PublicHandle

// Client can be used to fetch the provider metadata for a given issuer, and can
// also return the signing keys on demand.
//
// It should be created via `NewClient` to ensure it is initialized correctly.
type Client struct {
	md *ProviderMetadata

	hc *http.Client

	jwksCacheDuration    time.Duration
	jwksCacheLastUpdated time.Time
	jwksHandle           *keyset.Handle
	jwksMu               sync.Mutex
}

// ClientOpt is an option that can configure a client
type ClientOpt func(c *Client)

// WithHTTPClient will set a http.Client for the initial discovery, and key
// fetching. If not set, http.DefaultClient will be used.
func WithHTTPClient(hc *http.Client) func(c *Client) {
	return func(c *Client) {
		c.hc = hc
	}
}

// WithJWKSCacheDuration overrides the duration that we cache responses from the jwks endpoint.
func WithJWKSCacheDuration(d time.Duration) func(c *Client) {
	return func(c *Client) {
		c.jwksCacheDuration = d
	}
}

// NewClient will initialize a Client, performing the initial discovery.
func NewClient(ctx context.Context, issuer string, opts ...ClientOpt) (*Client, error) {
	c := &Client{
		md:                &ProviderMetadata{},
		hc:                http.DefaultClient,
		jwksCacheDuration: DefaultJWKSCacheDuration,
	}

	for _, o := range opts {
		o(c)
	}

	mdr, err := c.hc.Get(issuer + oidcwk)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", issuer+oidcwk, err)
	}
	err = json.NewDecoder(mdr.Body).Decode(c.md)
	_ = mdr.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error decoding provider metadata response: %v", err)
	}

	return c, nil
}

// Metadata returns the ProviderMetadata that was retrieved when the client was
// instantiated
func (c *Client) Metadata() *ProviderMetadata {
	return c.md
}

// PublicHandle returns a keyset handle for the issuer's JWKS. This will return
// a cached result if it exists and is still valid, otherwise will perform a
// HTTP request to retrieve it.
func (c *Client) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	if c.md.JWKSURI == "" {
		return nil, fmt.Errorf("metadata has no JWKS endpoint, cannot fetch keys")
	}

	if c.jwksHandle != nil && time.Now().Before(c.jwksCacheLastUpdated.Add(c.jwksCacheDuration)) {
		return c.jwksHandle, nil
	}

	res, err := c.hc.Get(c.md.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys from %s: %v", c.md.JWKSURI, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
	}
	jwksb, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading JWKS body: %w", err)
	}

	h, err := jwt.JWKSetToPublicKeysetHandle(jwksb)
	if err != nil {
		return nil, fmt.Errorf("creating handle from response: %w", err)
	}

	c.jwksCacheLastUpdated = time.Now()
	c.jwksHandle = h

	return h, nil
}
