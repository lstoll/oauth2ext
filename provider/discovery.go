package provider

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwt/remotejwks"
)

// Option configures a discovered provider.
type Option func(*Provider) error

// WithVerificationKeys overrides the key source advertised by discovery. The
// source is used from initial discovery onwards, while discovery metadata and
// issuer validation still take place.
func WithVerificationKeys(source jwt.KeySetSource) Option {
	return func(p *Provider) error {
		if source == nil {
			return fmt.Errorf("provider verification key source is required")
		}
		p.VerificationKeys = source
		return nil
	}
}

func DiscoverOIDCProvider(ctx context.Context, issuer string, options ...Option) (*Provider, error) {
	p := &Provider{
		oidcDiscoveryURL: strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
		discoveryIssuer:  issuer,
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("provider option is nil")
		}
		if err := option(p); err != nil {
			return nil, err
		}
	}

	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, fmt.Errorf("error performing initial metadata discovery: %w", err)
	}

	return p, nil
}

const maxProviderResponseBytes = 1 << 20

func (p *Provider) refreshIfNeeded(ctx context.Context) error {
	cacheFor := p.CacheDuration
	if cacheFor == 0 {
		cacheFor = DefaultCacheDuration
	}
	if p.cacheIsFresh(cacheFor) {
		return nil
	}

	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if p.cacheIsFresh(cacheFor) {
		return nil
	}

	// if we are a discovered provider, refresh the discovery metadata too.
	md, _ := p.snapshot()
	if p.oidcDiscoveryURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.oidcDiscoveryURL, nil)
		if err != nil {
			return fmt.Errorf("creating request for %s: %w", p.oidcDiscoveryURL, err)
		}
		req = req.WithContext(ctx)
		res, err := internal.HTTPClientFromContext(ctx, p.HTTPClient).Do(req)
		if err != nil {
			return fmt.Errorf("failed to get discovery metadata from %s: %v", p.oidcDiscoveryURL, err)
		}
		if res.StatusCode != http.StatusOK {
			_ = res.Body.Close()
			return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
		}
		mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			_ = res.Body.Close()
			return fmt.Errorf("expected content type %s, got: %s", "application/json", res.Header.Get("Content-Type"))
		}

		body, err := readBounded(res.Body, maxProviderResponseBytes)
		_ = res.Body.Close()
		if err != nil {
			return fmt.Errorf("reading discovery metadata response: %w", err)
		}
		var discovered OIDCProviderMetadata
		if err := jsonv2.Unmarshal(body, &discovered); err != nil {
			return fmt.Errorf("error decoding discovery metadata response: %v", err)
		}
		if discovered.Issuer != p.discoveryIssuer {
			return fmt.Errorf("discovery issuer %q does not match requested issuer %q", discovered.Issuer, p.discoveryIssuer)
		}
		md = &discovered
	}
	if md == nil {
		return fmt.Errorf("provider metadata is required")
	}

	p.cacheMu.RLock()
	override := p.VerificationKeys
	keys := p.keys
	p.cacheMu.RUnlock()
	if override != nil {
		keys = override
	} else {
		jwksURI := md.jwksuri()
		current, ok := keys.(*remotejwks.Source)
		if !ok || current.URL != jwksURI {
			keys = &remotejwks.Source{
				URL:           jwksURI,
				HTTPClient:    p.HTTPClient,
				CacheDuration: cacheFor,
			}
		}
	}
	if keys == nil {
		return fmt.Errorf("provider has no verification keys")
	}
	if _, err := keys.KeySet(ctx); err != nil {
		return fmt.Errorf("getting provider verification keys: %w", err)
	}

	p.cacheMu.Lock()
	p.Metadata = md
	if p.VerificationKeys == nil {
		p.keys = keys
	}
	p.cacheLastFetched = time.Now()
	p.cacheMu.Unlock()

	return nil
}

func (p *Provider) cacheIsFresh(cacheFor time.Duration) bool {
	p.cacheMu.RLock()
	lastFetched := p.cacheLastFetched
	p.cacheMu.RUnlock()
	return !lastFetched.IsZero() && time.Since(lastFetched) < cacheFor
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return body, nil
}
