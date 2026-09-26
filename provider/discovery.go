package provider

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"lds.li/oauth2ext/internal/httprevalidate"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwt/remotejwks"
)

const DefaultRequestTimeout = 30 * time.Second

// DiscoveryConfig contains optional discovery settings.
type DiscoveryConfig struct {
	HTTPClient *http.Client
	// FallbackRefreshInterval applies when discovery or JWKS responses provide
	// neither Cache-Control freshness nor Expires. Zero uses
	// DefaultRefreshInterval; negative values are rejected.
	FallbackRefreshInterval time.Duration
	// RequestTimeout bounds each discovery and JWKS request. Zero uses the
	// package default.
	RequestTimeout time.Duration
	// MinRefreshInterval is the shortest freshness the provider's caching
	// headers can set for discovery and JWKS, and the wait before retrying
	// after a failed refresh. Zero uses DefaultMinRefreshInterval; negative
	// values are rejected.
	MinRefreshInterval time.Duration
	// VerificationKeys overrides keys advertised by discovery. Discovery and
	// issuer validation still run. Keep this handle stable and update it with
	// Replace when trusted keys rotate.
	VerificationKeys *jwt.VerificationKeySet
}

// DiscoverOIDCProvider eagerly discovers issuer metadata and initial keys.
// Ordinary provider operations lazily call EnsureFresh according to HTTP
// freshness, while Run enables active refresh. VerificationKeys, when
// supplied, disables remote JWKS retrieval.
func DiscoverOIDCProvider(ctx context.Context, issuer string, configs ...DiscoveryConfig) (*Provider, error) {
	if len(configs) > 1 {
		return nil, fmt.Errorf("at most one discovery config may be supplied")
	}
	var config DiscoveryConfig
	if len(configs) == 1 {
		config = configs[0]
	}
	fallback := config.FallbackRefreshInterval
	if fallback == 0 {
		fallback = DefaultRefreshInterval
	}
	if fallback < 0 {
		return nil, fmt.Errorf("fallback refresh interval must not be negative")
	}
	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	if requestTimeout < 0 {
		return nil, fmt.Errorf("request timeout must not be negative")
	}
	minRefresh := config.MinRefreshInterval
	if minRefresh == 0 {
		minRefresh = DefaultMinRefreshInterval
	}
	if minRefresh < 0 {
		return nil, fmt.Errorf("minimum refresh interval must not be negative")
	}
	p := &Provider{
		oidcDiscoveryURL:        strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
		discoveryIssuer:         issuer,
		VerificationKeys:        config.VerificationKeys,
		httpClient:              config.HTTPClient,
		fallbackRefreshInterval: config.FallbackRefreshInterval,
		requestTimeout:          requestTimeout,
		minRefreshInterval:      minRefresh,
		metadataResource: httprevalidate.New(httprevalidate.Config{
			URL:                strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
			HTTPClient:         config.HTTPClient,
			AcceptedMediaTypes: []string{"application/json"},
			MaxBodyBytes:       maxProviderResponseBytes,
			RequestTimeout:     requestTimeout,
			MinFreshness:       minRefresh,
		}, fallback),
	}
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, fmt.Errorf("error performing initial metadata discovery: %w", err)
	}
	return p, nil
}

const maxProviderResponseBytes = 1 << 20

// refreshIfNeeded runs on the request path. Once the provider has metadata
// and keys, a failed refresh keeps serving them: an unreachable provider must
// not stop verification with keys it published earlier. Refresh and Run
// report refresh errors to callers that monitor them.
func (p *Provider) refreshIfNeeded(ctx context.Context) error {
	err := p.refresh(ctx, false)
	if err != nil && p.snapshot() != nil && p.keySet() != nil {
		return nil
	}
	return err
}

func (p *Provider) refresh(ctx context.Context, force bool) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if p.metadataResource != nil {
		apply := func(body []byte) error {
			var candidate OIDCProviderMetadata
			if err := unmarshalMetadata(body, &candidate); err != nil {
				return fmt.Errorf("error decoding discovery metadata response: %w", err)
			}
			if candidate.Issuer != p.discoveryIssuer {
				return fmt.Errorf("discovery issuer %q does not match requested issuer %q", candidate.Issuer, p.discoveryIssuer)
			}
			p.pendingMetadata = candidate.Clone()
			return nil
		}
		var err error
		if force {
			_, err = p.metadataResource.Revalidate(ctx, apply)
		} else {
			_, err = p.metadataResource.Refresh(ctx, apply)
		}
		if err != nil {
			return fmt.Errorf("failed to get discovery metadata from %s: %w", p.oidcDiscoveryURL, err)
		}
	}

	md := p.pendingMetadata
	if md == nil {
		md = p.snapshot()
	}
	if md == nil {
		return fmt.Errorf("provider metadata is required")
	}
	override := p.VerificationKeys
	refresher := p.keyRefresher
	currentKeys := p.keys
	if override != nil {
		if p.pendingMetadata != nil {
			p.metadataMu.Lock()
			p.metadata = md
			p.metadataMu.Unlock()
			p.pendingMetadata = nil
		}
		return nil
	}

	jwksURI := md.jwksuri()
	if refresher == nil || p.keyRefresherURL != jwksURI {
		var target *jwt.VerificationKeySet
		if refresher != nil {
			target = currentKeys
			// Older keys remain usable, so don't refetch a failing new
			// jwks_uri on every request. Forced refreshes still retry.
			if !force && p.jwksOpenRetryURL == jwksURI && time.Now().Before(p.jwksOpenRetryAt) {
				return fmt.Errorf("getting provider verification keys: waiting to retry %s", jwksURI)
			}
		}
		opened, err := remotejwks.Open(ctx, remotejwks.Config{
			URL:                     jwksURI,
			HTTPClient:              p.httpClient,
			FallbackRefreshInterval: p.fallbackRefreshInterval,
			VerificationKeySet:      target,
			RequestTimeout:          p.requestTimeout,
			MinRefreshInterval:      p.minRefreshInterval,
		})
		if err != nil {
			if refresher != nil {
				p.jwksOpenRetryURL = jwksURI
				p.jwksOpenRetryAt = time.Now().Add(p.minRefreshInterval)
			}
			return fmt.Errorf("getting provider verification keys: %w", err)
		}
		refresher = opened
		p.jwksOpenRetryURL, p.jwksOpenRetryAt = "", time.Time{}
	} else if err := refreshSource(ctx, refresher, force); err != nil {
		return fmt.Errorf("getting provider verification keys: %w", err)
	}
	keys := refresher.VerificationKeySet()
	if keys == nil {
		return fmt.Errorf("provider has no verification keys")
	}
	if p.keys == nil {
		p.keys = keys
	}
	p.keyRefresher = refresher
	p.keyRefresherURL = jwksURI
	if p.pendingMetadata != nil {
		p.metadataMu.Lock()
		p.metadata = md
		p.metadataMu.Unlock()
		p.pendingMetadata = nil
	}
	return nil
}

// unmarshalMetadata preserves extension members while rejecting case variants
// of known names. Such variants could otherwise be mistaken for extensions by
// this implementation and for protocol fields by another implementation.
func unmarshalMetadata(body []byte, into *OIDCProviderMetadata) error {
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(body, &members); err != nil {
		return err
	}
	var known []string
	exactNames := make(map[string]struct{})
	typ := reflect.TypeFor[OIDCProviderMetadata]()
	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			known = append(known, name)
			exactNames[name] = struct{}{}
		}
	}
	for name := range members {
		if _, exact := exactNames[name]; exact {
			continue
		}
		for _, fieldName := range known {
			if strings.EqualFold(name, fieldName) {
				return fmt.Errorf("ambiguous discovery metadata member %q", name)
			}
		}
	}
	return jsonv2.Unmarshal(body, into)
}

func refreshSource(ctx context.Context, source *remotejwks.Source, force bool) error {
	if force {
		return source.Refresh(ctx)
	}
	return source.EnsureFresh(ctx)
}
