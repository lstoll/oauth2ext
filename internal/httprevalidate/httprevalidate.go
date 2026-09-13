// Package httprevalidate fetches bounded HTTP documents with conditional ETag
// revalidation. Protocol packages own parsing and state replacement.
package httprevalidate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"lds.li/oauth2ext/internal"
)

var (
	ErrSizeLimit          = errors.New("HTTP response exceeds size limit")
	ErrNotModifiedNoCache = errors.New("HTTP 304 response without a cached representation")
)

const MinRefreshInterval = time.Second

type Config struct {
	URL                string
	HTTPClient         *http.Client
	AcceptedMediaTypes []string
	MaxBodyBytes       int64
	// RequestTimeout bounds each HTTP request. Zero means no additional
	// timeout; callers that expose this package should normally provide a
	// sensible default.
	RequestTimeout time.Duration
	// Now supplies the clock used for freshness calculations. It is primarily
	// useful for deterministic tests.
	Now func() time.Time
}

type result struct {
	Body        []byte
	ETag        string
	NotModified bool
	CacheFor    time.Duration
	Store       bool
}

// Resource owns HTTP cache and revalidation state for one document.
type Resource struct {
	config   Config
	fallback time.Duration
	mu       sync.Mutex
	etag     string
	last     time.Time
	cacheFor time.Duration
	cacheSet bool
	hasBody  bool
	body     []byte
}

func New(config Config, fallback time.Duration) *Resource {
	return &Resource{config: config, fallback: fallback}
}

// Refresh revalidates when the cached document is stale. apply is called under
// the resource's refresh lock for each newly fetched representation, before it
// becomes cached. This lets callers update their parsed representation without
// duplicating ETag, freshness, or singleflight state.
func (r *Resource) Refresh(ctx context.Context, apply func([]byte) error) (bool, error) {
	return r.refresh(ctx, apply, false)
}

// Revalidate always makes a conditional request, even while a cached document
// remains fresh.
func (r *Resource) Revalidate(ctx context.Context, apply func([]byte) error) (bool, error) {
	return r.refresh(ctx, apply, true)
}

func (r *Resource) refresh(ctx context.Context, apply func([]byte) error, force bool) (changed bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cacheFor := r.cacheFor
	if !r.cacheSet {
		cacheFor = r.fallback
	}
	if !force && cacheFor > 0 && !r.last.IsZero() && r.now().Sub(r.last) < cacheFor {
		return false, nil
	}
	result, err := get(ctx, r.config, r.etag, cacheFor)
	if err != nil {
		return false, err
	}
	if result.NotModified {
		if !r.hasBody {
			return false, ErrNotModifiedNoCache
		}
		r.last = r.now()
		r.cacheFor = result.CacheFor
		r.cacheSet = true
		if result.ETag != "" {
			r.etag = result.ETag
		}
		if !result.Store {
			r.body = nil
			r.etag = ""
			r.hasBody = false
		}
		return false, nil
	}
	if apply != nil {
		if err := apply(result.Body); err != nil {
			return false, err
		}
	}
	if result.Store {
		r.last = r.now()
		r.cacheFor = result.CacheFor
		r.cacheSet = true
		r.etag = result.ETag
		r.body = append(r.body[:0], result.Body...)
		r.hasBody = true
	} else {
		r.body = nil
		r.etag = ""
		r.hasBody = false
		// Keep cacheSet true with a zero freshness lifetime: no-store is
		// immediately due, while the representation and validator are gone.
		r.cacheSet = true
		r.cacheFor = 0
		r.last = r.now()
	}
	return true, nil
}

// RefreshIn returns the remaining freshness lifetime. A stale, no-cache, or
// no-store resource returns zero. Before the first response it returns the
// configured fallback interval.
func (r *Resource) RefreshIn() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.cacheSet {
		return r.fallback
	}
	remaining := r.cacheFor - r.now().Sub(r.last)
	return max(remaining, 0)
}

func (r *Resource) now() time.Time {
	if r.config.Now != nil {
		return r.config.Now()
	}
	return time.Now()
}

func get(ctx context.Context, config Config, etag string, fallback time.Duration) (result, error) {
	if config.URL == "" || config.MaxBodyBytes <= 0 || len(config.AcceptedMediaTypes) == 0 {
		return result{}, fmt.Errorf("invalid HTTP revalidation config")
	}
	requestCtx := ctx
	if config.RequestTimeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, config.RequestTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, config.URL, nil)
	if err != nil {
		return result{}, fmt.Errorf("creating request for %s: %w", config.URL, err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := internal.HTTPClientFromContext(ctx, config.HTTPClient).Do(req)
	if err != nil {
		return result{}, fmt.Errorf("requesting %s: %w", config.URL, err)
	}
	defer res.Body.Close()
	receivedAt := time.Now()
	if config.Now != nil {
		receivedAt = config.Now()
	}
	policy := parseCachePolicy(res.Header, fallback, receivedAt)
	out := result{ETag: res.Header.Get("ETag"), CacheFor: policy.cacheFor, Store: policy.store}
	if res.StatusCode == http.StatusNotModified {
		out.NotModified = true
		return out, nil
	}
	if res.StatusCode != http.StatusOK {
		return result{}, fmt.Errorf("requesting %s: expected status %d, got %d", config.URL, http.StatusOK, res.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil || !slices.Contains(config.AcceptedMediaTypes, mediaType) {
		return result{}, fmt.Errorf("requesting %s: expected content type %s, got %s", config.URL, strings.Join(config.AcceptedMediaTypes, ", "), res.Header.Get("Content-Type"))
	}
	out.Body, err = ReadBounded(res.Body, config.MaxBodyBytes)
	if err != nil {
		return result{}, fmt.Errorf("reading %s: %w", config.URL, err)
	}
	return out, nil
}

func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds %d byte limit", ErrSizeLimit, limit)
	}
	return body, nil
}

type cachePolicy struct {
	cacheFor time.Duration
	store    bool
}

func parseCachePolicy(header http.Header, fallback time.Duration, receivedAt time.Time) cachePolicy {
	policy := cachePolicy{cacheFor: fallback, store: true}
	var maxAge *int64
	noCache := false
	for directive := range strings.SplitSeq(header.Get("Cache-Control"), ",") {
		name, value, hasValue := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(name) {
		case "no-store":
			policy.store = false
		case "no-cache":
			noCache = true
		case "max-age":
			if !hasValue {
				continue
			}
			seconds, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
			if err == nil && seconds >= 0 {
				maxAge = &seconds
			}
		}
	}
	if !policy.store || noCache {
		policy.cacheFor = 0
		return policy
	}
	if maxAge == nil {
		if expires, err := http.ParseTime(header.Get("Expires")); err == nil {
			base := receivedAt
			if date, err := http.ParseTime(header.Get("Date")); err == nil {
				base = date
			}
			age, _ := strconv.ParseInt(header.Get("Age"), 10, 64)
			policy.cacheFor = max(expires.Sub(base)-ageDuration(age), 0)
		}
		return policy
	}
	age, _ := strconv.ParseInt(header.Get("Age"), 10, 64)
	remaining := max(*maxAge-max(age, 0), 0)
	const maxCacheSeconds = int64((1<<63 - 1) / int64(time.Second))
	if remaining > maxCacheSeconds {
		remaining = maxCacheSeconds
	}
	policy.cacheFor = time.Duration(remaining) * time.Second
	return policy
}

func ageDuration(age int64) time.Duration {
	if age <= 0 {
		return 0
	}
	const maxSeconds = int64((1<<63 - 1) / int64(time.Second))
	if age >= maxSeconds {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(age) * time.Second
}

// Wait sleeps until a refresh deadline, clamping immediate deadlines to a
// small interval so active refresh loops cannot spin. Context cancellation is
// observed promptly and returned unchanged.
func Wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		delay = MinRefreshInterval
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
