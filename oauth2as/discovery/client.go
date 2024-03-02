package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

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

	backgroundRefresh         bool
	backgroundRefreshInterval time.Duration
	refresher                 *refresher
	jwksMu                    sync.Mutex
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

// WithBackgroundJWKSRefresh starts a goroutine in the background to refresh the
// jwks every interval time, to ensure that remotely rotated keys are accounted
// for. If the interval is 0, a default of 15 minutes will be used. This routine
// will log errors via slog.
func WithBackgroundJWKSRefresh(interval time.Duration) func(c *Client) {
	return func(c *Client) {
		c.backgroundRefresh = true
		c.backgroundRefreshInterval = interval
	}
}

// NewClient will initialize a Client, performing the initial discovery.
func NewClient(ctx context.Context, issuer string, opts ...ClientOpt) (*Client, error) {
	c := &Client{
		md: &ProviderMetadata{},
		hc: http.DefaultClient,
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

	c.refresher = &refresher{
		hc:      c.hc,
		jwksuri: c.md.JWKSURI,
		stop:    make(chan struct{}, 1),
	}

	if err := c.RefreshJWKS(ctx); err != nil {
		return nil, fmt.Errorf("initial jwks fetch: %w", err)
	}

	if c.backgroundRefresh {
		if c.backgroundRefreshInterval == 0 {
			c.backgroundRefreshInterval = 15 * time.Minute
		}
		go c.refresher.RunRefreshRoutine(c.backgroundRefreshInterval)
		runtime.SetFinalizer(c, func(c *Client) {
			c.refresher.stop <- struct{}{}
		})
	}

	return c, nil
}

// Metadata returns the ProviderMetadata that was retrieved when the client was
// instantiated
func (c *Client) Metadata() *ProviderMetadata {
	return c.md
}

// RefreshJWKS loads the current JWKS keyset from the issuer. This may need to
// be done periodically to account for key rotation.
func (c *Client) RefreshJWKS(ctx context.Context) error {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	return c.refresher.Refresh(ctx)
}

// PublicHandle returns the current keyset handle for the issuer's JWKS. If keys
// are rotated remotely, this may need to be refreshed.
func (c *Client) PublicHandle() *keyset.Handle {
	return c.refresher.handle
}

// refresher is the embedded type that the refresh goroutine points to. this
// allows us to set a finalizer on the parent type when it gets GC'd to stop the
// refresh routine. If the routine had a reference to the parent struct, it
// would never get GC'd
type refresher struct {
	hc      *http.Client
	jwksuri string
	handle  *keyset.Handle
	stop    chan struct{}
	stopped bool // for testing
}

func (r *refresher) RunRefreshRoutine(interval time.Duration) {
	for {
		select {
		case <-time.After(interval):
			if err := r.Refresh(context.Background()); err != nil {
				slog.Error("failed to refresh jwks", "component", "oidc/discovery", "jwksurl", r.jwksuri, "err", err.Error())
			}
		case <-r.stop:
			r.stopped = true
			return
		}
	}
}

func (r *refresher) Refresh(ctx context.Context) error {
	req, err := http.NewRequest(http.MethodGet, r.jwksuri, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", r.jwksuri, err)
	}
	req = req.WithContext(ctx)
	res, err := r.hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get keys from %s: %v", r.jwksuri, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
	}
	jwksb, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS body: %w", err)
	}

	h, err := jwt.JWKSetToPublicKeysetHandle(jwksb)
	if err != nil {
		return fmt.Errorf("creating handle from response: %w", err)
	}

	r.handle = h
	return nil
}
