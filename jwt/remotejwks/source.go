package remotejwks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/jwt"
)

const (
	// DefaultCacheDuration is used when [Source.CacheDuration] is zero.
	DefaultCacheDuration = 10 * time.Minute
	maxJWKSBytes         = 1 << 20 // 1 MiB
)

var validJWKSContentTypes = []string{
	"application/json",
	"application/jwk-set+json",
}

// Source refreshes one stable VerificationKeySet from URL. Call Refresh from
// the application's chosen reload schedule; it retains TTL, singleflight, and
// optional stale-on-error behavior for callers that choose to invoke it often.
// Fields must not be modified after the first call to Refresh or JWKS.
type Source struct {
	// URL is the jwks_uri to GET. Required.
	URL string
	// HTTPClient is used when the context does not carry oauth2.HTTPClient.
	HTTPClient *http.Client
	// CacheDuration is how long a successful fetch is reused. Defaults to
	// [DefaultCacheDuration].
	CacheDuration time.Duration
	// StaleOnError returns the last successful key set when a refresh fails.
	// Without it, a failed refresh returns the fetch error even if older keys
	// are cached.
	StaleOnError bool

	mu          sync.Mutex
	lastFetched time.Time
	raw         []byte
	parsed      *jwt.VerificationKeySet
	now         func() time.Time
}

// Refresh fetches when needed and returns Source's stable verification-key-set
// handle. A successful refresh updates that handle atomically.
func (s *Source) Refresh(ctx context.Context) (*jwt.VerificationKeySet, error) {
	parsed, _, err := s.get(ctx)
	return parsed, err
}

// JWKS returns a copy of the cached JWKS document, fetching it when the TTL
// has expired.
func (s *Source) JWKS(ctx context.Context) ([]byte, error) {
	_, raw, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(raw), nil
}

func (s *Source) get(ctx context.Context) (*jwt.VerificationKeySet, []byte, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: source is required")
	}
	if s.URL == "" {
		return nil, nil, fmt.Errorf("jwt/remotejwks: URL is required")
	}

	cacheFor := s.CacheDuration
	if cacheFor == 0 {
		cacheFor = DefaultCacheDuration
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowTime()
	if s.freshLocked(now, cacheFor) {
		return s.parsed, s.raw, nil
	}

	raw, parsed, err := s.fetch(ctx)
	if err != nil {
		if s.StaleOnError && s.parsed != nil {
			return s.parsed, s.raw, nil
		}
		return nil, nil, err
	}
	s.raw = raw
	if s.parsed == nil {
		s.parsed = parsed
	} else if err := s.parsed.Replace(parsed); err != nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: replacing JWKS from %s: %w", s.URL, err)
	}
	s.lastFetched = now
	return s.parsed, raw, nil
}

func (s *Source) freshLocked(now time.Time, cacheFor time.Duration) bool {
	return s.parsed != nil && !s.lastFetched.IsZero() && now.Sub(s.lastFetched) < cacheFor
}

func (s *Source) nowTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Source) fetch(ctx context.Context) ([]byte, *jwt.VerificationKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: creating request for %s: %w", s.URL, err)
	}
	res, err := internal.HTTPClientFromContext(ctx, s.HTTPClient).Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: fetching JWKS from %s: %w", s.URL, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("jwt/remotejwks: fetching JWKS from %s: expected status %d, got %d", s.URL, http.StatusOK, res.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || !slices.Contains(validJWKSContentTypes, mediaType) {
		return nil, nil, fmt.Errorf("jwt/remotejwks: fetching JWKS from %s: expected content type %s, got %s", s.URL, strings.Join(validJWKSContentTypes, ", "), res.Header.Get("Content-Type"))
	}
	body, err := readBounded(res.Body, maxJWKSBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: reading JWKS from %s: %w", s.URL, err)
	}
	parsed, err := jwt.ParseVerificationKeySet(body)
	if err != nil {
		return nil, nil, fmt.Errorf("jwt/remotejwks: parsing JWKS from %s: %w", s.URL, err)
	}
	return body, parsed, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds %d byte limit", jwt.ErrSizeLimit, limit)
	}
	return body, nil
}
