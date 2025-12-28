package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/internal"
)

type discoveryOpts struct{}

type DiscoveryOpt func(*discoveryOpts)

func DiscoverOIDCProvider(ctx context.Context, issuer string, opts ...DiscoveryOpt) (*Provider, error) {
	p := &Provider{
		oidcDiscoveryURL: issuer + "/.well-known/openid-configuration",
	}

	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, fmt.Errorf("error performing initial metadata discovery: %w", err)
	}

	return p, nil
}

var validJWKSContentTypes = []string{
	"application/json",
	"application/jwk-set+json",
}

func (p *Provider) refreshIfNeeded(ctx context.Context) error {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	cacheFor := p.CacheDuration
	if cacheFor == 0 {
		cacheFor = DefaultCacheDuration
	}

	if !p.cacheLastFetched.IsZero() && time.Since(p.cacheLastFetched) < cacheFor {
		return nil
	}

	// if we are a discovered provider, refresh the discovery metadata too.
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
		defer func() { _ = res.Body.Close() }()

		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
		}
		if res.Header.Get("Content-Type") != "application/json" {
			return fmt.Errorf("expected content type %s, got: %s", "application/json", res.Header.Get("Content-Type"))
		}

		var md OIDCProviderMetadata
		err = json.NewDecoder(res.Body).Decode(&md)
		if err != nil {
			return fmt.Errorf("error decoding discovery metadata response: %v", err)
		}
		p.Metadata = &md
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Metadata.jwksuri(), nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", p.Metadata.jwksuri(), err)
	}
	req = req.WithContext(ctx)
	res, err := internal.HTTPClientFromContext(ctx, p.HTTPClient).Do(req)
	if err != nil {
		return fmt.Errorf("failed to get keys from %s: %v", p.Metadata.jwksuri(), err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
	}
	if !slices.Contains(validJWKSContentTypes, res.Header.Get("Content-Type")) {
		return fmt.Errorf("expected content type %s, got: %s", strings.Join(validJWKSContentTypes, ", "), res.Header.Get("Content-Type"))
	}
	jwksb, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS body: %w", err)
	}

	p.cachedJWKS = jwksb
	handle, err := jwt.JWKSetToPublicKeysetHandle(jwksb)
	if err != nil {
		return fmt.Errorf("creating public keyset handle from JWKS: %w", err)
	}

	p.cachedHandle = handle
	p.cacheLastFetched = time.Now()

	return nil
}
