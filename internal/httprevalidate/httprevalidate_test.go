package httprevalidate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCachePolicy(t *testing.T) {
	for _, test := range []struct {
		name     string
		header   string
		age      string
		cacheFor time.Duration
		store    bool
	}{
		{"fallback", "", "", time.Minute, true},
		{"max age", "max-age=120", "", 2 * time.Minute, true},
		{"age", "max-age=120", "90", 30 * time.Second, true},
		{"expired", "max-age=120", "121", 0, true},
		{"no cache", "max-age=120, no-cache", "", 0, true},
		{"no store", "max-age=120, no-store", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			header.Set("Cache-Control", test.header)
			header.Set("Age", test.age)
			got := parseCachePolicy(header, time.Minute, time.Now())
			if got.cacheFor != test.cacheFor || got.store != test.store {
				t.Fatalf("policy = %#v, want cacheFor=%v store=%v", got, test.cacheFor, test.store)
			}
		})
	}
}

func TestCachePolicyUsesExpiresWithoutCacheControl(t *testing.T) {
	header := make(http.Header)
	received := time.Date(2026, 9, 13, 12, 0, 5, 0, time.UTC)
	header.Set("Date", received.Add(-2*time.Second).UTC().Format(http.TimeFormat))
	header.Set("Expires", received.Add(8*time.Second).UTC().Format(http.TimeFormat))
	header.Set("Age", "3")
	policy := parseCachePolicy(header, time.Minute, received)
	if !policy.store || policy.cacheFor != 7*time.Second {
		t.Fatalf("policy = %#v, want a positive expiry-based lifetime", policy)
	}
}

func TestResourceRefreshInReportsRemainingTime(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	resource := New(Config{
		URL:                "https://issuer.example/jwks",
		AcceptedMediaTypes: []string{"application/json"},
		MaxBodyBytes:       1024,
		Now:                func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripper(func(*http.Request) *http.Response {
			return response(http.StatusOK, "max-age=10", `{}`)
		})},
	}, time.Minute)
	if _, err := resource.Refresh(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Second)
	if got := resource.RefreshIn(); got != 7*time.Second {
		t.Fatalf("RefreshIn = %v, want 7s", got)
	}
	now = now.Add(8 * time.Second)
	if got := resource.RefreshIn(); got != 0 {
		t.Fatalf("stale RefreshIn = %v, want zero", got)
	}
}

func TestResourceNoStoreIsImmediatelyDue(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	hits := 0
	resource := New(Config{
		URL:                "https://issuer.example/jwks",
		AcceptedMediaTypes: []string{"application/json"},
		MaxBodyBytes:       1024,
		Now:                func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripper(func(*http.Request) *http.Response {
			hits++
			return response(http.StatusOK, "no-store", `{}`)
		})},
	}, time.Minute)
	for range 2 {
		if _, err := resource.Refresh(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if got := resource.RefreshIn(); got != 0 {
			t.Fatalf("no-store RefreshIn = %v, want zero", got)
		}
	}
	if hits != 2 {
		t.Fatalf("requests = %d, want 2", hits)
	}
}

func TestResourceRequestTimeoutIncludesURL(t *testing.T) {
	resource := New(Config{
		URL:                "https://issuer.example/jwks",
		AcceptedMediaTypes: []string{"application/json"},
		MaxBodyBytes:       1024,
		RequestTimeout:     time.Millisecond,
		HTTPClient: &http.Client{Transport: roundTripper(func(req *http.Request) *http.Response {
			<-req.Context().Done()
			return nil
		})},
	}, time.Minute)
	_, err := resource.Refresh(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "https://issuer.example/jwks") {
		t.Fatalf("error = %v, want URL context", err)
	}
}

func TestResourceRejectsUncachedNotModified(t *testing.T) {
	resource := New(Config{
		URL:                "https://issuer.example/jwks",
		HTTPClient:         &http.Client{Transport: roundTripper(func(*http.Request) *http.Response { return response(http.StatusNotModified, "", "") })},
		AcceptedMediaTypes: []string{"application/json"},
		MaxBodyBytes:       1024,
	}, time.Minute)
	_, err := resource.Refresh(context.Background(), nil)
	if !errors.Is(err, ErrNotModifiedNoCache) {
		t.Fatalf("error = %v, want ErrNotModifiedNoCache", err)
	}
}

func TestResourceDoesNotStoreNoStoreResponse(t *testing.T) {
	hits := 0
	resource := New(Config{
		URL: "https://issuer.example/jwks",
		HTTPClient: &http.Client{Transport: roundTripper(func(*http.Request) *http.Response {
			hits++
			return response(http.StatusOK, "no-store", `{}`)
		})},
		AcceptedMediaTypes: []string{"application/json"},
		MaxBodyBytes:       1024,
	}, time.Minute)
	for range 2 {
		if _, err := resource.Refresh(context.Background(), func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 2 {
		t.Fatalf("requests = %d, want 2", hits)
	}
}

type roundTripper func(*http.Request) *http.Response

func (f roundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request), nil
}

func response(status int, cacheControl, body string) *http.Response {
	header := make(http.Header)
	header.Set("Cache-Control", cacheControl)
	header.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
