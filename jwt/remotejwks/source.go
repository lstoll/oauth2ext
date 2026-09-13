package remotejwks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"lds.li/oauth2ext/internal/httprevalidate"
	"lds.li/oauth2ext/jwt"
)

const (
	// DefaultRefreshInterval is used when Config.FallbackRefreshInterval is zero.
	DefaultRefreshInterval = 10 * time.Minute
	maxJWKSBytes           = 1 << 20 // 1 MiB
	DefaultRequestTimeout  = 30 * time.Second
)

// Config configures a Source opened with Open.
type Config struct {
	URL        string
	HTTPClient *http.Client
	// VerificationKeySet, when non-nil, is the stable handle updated by this
	// source. This lets a caller retain one handle across jwks_uri changes.
	VerificationKeySet *jwt.VerificationKeySet
	// FallbackRefreshInterval applies when the JWKS response provides neither
	// Cache-Control freshness nor Expires. Zero uses DefaultRefreshInterval;
	// negative values are rejected.
	FallbackRefreshInterval time.Duration
	// RequestTimeout bounds each JWKS request. Zero uses DefaultRequestTimeout.
	RequestTimeout time.Duration
}

var validJWKSContentTypes = []string{
	"application/json",
	"application/jwk-set+json",
}

// Source refreshes one stable VerificationKeySet from a remote JWKS. Its
// revalidation state is shared with other HTTP-backed protocol documents by
// internal/httprevalidate.
type Source struct {
	resource *httprevalidate.Resource
	keySet   *jwt.VerificationKeySet
}

// Open performs the initial JWKS fetch. On success, VerificationKeySet returns
// a stable handle whose contents are atomically replaced by later refreshes.
func Open(ctx context.Context, config Config) (*Source, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("jwt/remotejwks: URL is required")
	}
	fallback := config.FallbackRefreshInterval
	if fallback == 0 {
		fallback = DefaultRefreshInterval
	}
	if fallback < 0 {
		return nil, fmt.Errorf("jwt/remotejwks: fallback refresh interval must not be negative")
	}
	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultRequestTimeout
	}
	if requestTimeout < 0 {
		return nil, fmt.Errorf("jwt/remotejwks: request timeout must not be negative")
	}
	s := &Source{
		resource: httprevalidate.New(httprevalidate.Config{
			URL:                config.URL,
			HTTPClient:         config.HTTPClient,
			AcceptedMediaTypes: validJWKSContentTypes,
			MaxBodyBytes:       maxJWKSBytes,
			RequestTimeout:     requestTimeout,
		}, fallback),
		keySet: config.VerificationKeySet,
	}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Refresh always conditionally revalidates the remote JWKS. A successful
// refresh updates Source's stable verification-key-set handle atomically.
func (s *Source) Refresh(ctx context.Context) error {
	return s.refresh(ctx, true)
}

// EnsureFresh revalidates only when the cached JWKS is stale.
func (s *Source) EnsureFresh(ctx context.Context) error {
	return s.refresh(ctx, false)
}

func (s *Source) refresh(ctx context.Context, force bool) error {
	if s == nil || s.resource == nil {
		return fmt.Errorf("jwt/remotejwks: source is required")
	}
	var err error
	if force {
		_, err = s.resource.Revalidate(ctx, s.apply)
	} else {
		_, err = s.resource.Refresh(ctx, s.apply)
	}
	if err != nil {
		if errors.Is(err, httprevalidate.ErrSizeLimit) {
			err = fmt.Errorf("%w: %v", jwt.ErrSizeLimit, err)
		}
		return fmt.Errorf("jwt/remotejwks: refreshing JWKS: %w", err)
	}
	return nil
}

func (s *Source) apply(body []byte) error {
	parsed, err := jwt.ParseVerificationJWKS(body)
	if err != nil {
		return fmt.Errorf("jwt/remotejwks: parsing JWKS: %w", err)
	}
	if s.keySet == nil {
		s.keySet = parsed
		return nil
	}
	if err := s.keySet.Replace(parsed); err != nil {
		return fmt.Errorf("jwt/remotejwks: replacing JWKS: %w", err)
	}
	return nil
}

func (s *Source) VerificationKeySet() *jwt.VerificationKeySet {
	if s == nil {
		return nil
	}
	return s.keySet
}

// RefreshIn reports the remaining freshness lifetime for the active
// lifecycle. Zero means an immediate refresh is due.
func (s *Source) RefreshIn() time.Duration {
	if s == nil || s.resource == nil {
		return 0
	}
	return s.resource.RefreshIn()
}

// Run actively refreshes the source as each response's cache lifetime
// approaches expiry. It stops on a refresh error or context cancellation;
// callers own retry policy and lifecycle supervision.
func (s *Source) Run(ctx context.Context) error {
	if s == nil || s.resource == nil {
		return fmt.Errorf("jwt/remotejwks: source is required")
	}
	for {
		if err := s.EnsureFresh(ctx); err != nil {
			return err
		}
		if err := httprevalidate.Wait(ctx, s.RefreshIn()); err != nil {
			return err
		}
	}
}
