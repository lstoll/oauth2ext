package remotejwks

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwttest"
)

func TestKeySetFetchesAndCaches(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	ks := &Source{URL: srv.URL, CacheDuration: time.Minute}
	first, err := ks.Refresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second, err := ks.Refresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("cached Get returned a different key set")
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches: got %d, want 1", hits.Load())
	}
}

func TestKeySetRefreshesAfterTTL(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	srv := httptest.NewServer(jwksHandler(&hits, signer.JWKS()))
	t.Cleanup(srv.Close)

	now := time.Unix(1_700_000_000, 0)
	ks := &Source{
		URL:           srv.URL,
		CacheDuration: time.Minute,
		now:           func() time.Time { return now },
	}
	if _, err := ks.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := ks.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("fetches: got %d, want 2", hits.Load())
	}
}

func TestKeySetSingleflight(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	ks := &Source{URL: srv.URL}
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, err := ks.Refresh(t.Context())
			errCh <- err
		})
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches: got %d, want 1", hits.Load())
	}
}

func TestJWKSReturnsCopy(t *testing.T) {
	signer := jwttest.NewSigner(t)
	srv := httptest.NewServer(jwksHandler(nil, signer.JWKS()))
	t.Cleanup(srv.Close)

	ks := &Source{URL: srv.URL}
	first, err := ks.JWKS(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(first)
	first[0] ^= 0xff
	second, err := ks.JWKS(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatal("mutating returned JWKS changed cache")
	}
}

func TestStaleOnError(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	now := time.Unix(1_700_000_000, 0)
	ks := &Source{
		URL:           srv.URL,
		CacheDuration: time.Minute,
		StaleOnError:  true,
		now:           func() time.Time { return now },
	}
	first, err := ks.Refresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	now = now.Add(time.Minute)
	got, err := ks.Refresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatal("stale Get returned a different key set")
	}
}

func TestKeySetRefreshErrorWithoutStale(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	now := time.Unix(1_700_000_000, 0)
	ks := &Source{
		URL:           srv.URL,
		CacheDuration: time.Minute,
		now:           func() time.Time { return now },
	}
	if _, err := ks.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	now = now.Add(time.Minute)
	if _, err := ks.Refresh(t.Context()); err == nil {
		t.Fatal("expected refresh error")
	}
}

func TestKeySetRejectsEmptyURL(t *testing.T) {
	if _, err := (&Source{}).Refresh(t.Context()); err == nil {
		t.Fatal("empty URL accepted")
	}
}

func TestKeySetRejectsWrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	if _, err := (&Source{URL: srv.URL}).Refresh(t.Context()); err == nil {
		t.Fatal("expected content type error")
	}
}

func TestKeySetRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte{' '}, maxJWKSBytes+1))
	}))
	t.Cleanup(srv.Close)
	_, err := (&Source{URL: srv.URL}).Refresh(t.Context())
	if err == nil || !errors.Is(err, jwt.ErrSizeLimit) {
		t.Fatalf("error: got %v, want ErrSizeLimit", err)
	}
}

func TestKeySetRejectsInvalidJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)
	_, err := (&Source{URL: srv.URL}).Refresh(t.Context())
	if err == nil || !errors.Is(err, jwt.ErrKey) {
		t.Fatalf("error: got %v, want ErrKey", err)
	}
}

func TestKeySetUsesContextHTTPClient(t *testing.T) {
	signer := jwttest.NewSigner(t)
	srv := httptest.NewTLSServer(jwksHandler(nil, signer.JWKS()))
	t.Cleanup(srv.Close)

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, srv.Client())
	if _, err := (&Source{URL: srv.URL}).Refresh(ctx); err != nil {
		t.Fatal(err)
	}
}

func jwksHandler(hits *atomic.Int64, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}
}
