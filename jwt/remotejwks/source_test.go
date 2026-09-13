package remotejwks

import (
	"bytes"
	"context"
	"encoding/json"
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
	srv := httptest.NewServer(jwksHandler(&hits, signer.JWKS(), "max-age=60"))
	t.Cleanup(srv.Close)

	source, err := Open(t.Context(), Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	first := source.VerificationKeySet()
	if err := source.EnsureFresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if source.VerificationKeySet() != first {
		t.Fatal("Refresh replaced the verification key set handle")
	}
	if hits.Load() != 1 {
		t.Fatalf("fetches: got %d, want 1", hits.Load())
	}
}

func TestRefreshEmptyJWKSRevokesKeysAndBadRefreshRetainsLastGoodSet(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var body atomic.Value
	body.Store(signer.JWKS())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body.Load().([]byte))
	}))
	t.Cleanup(srv.Close)
	keys, err := jwt.ParseVerificationJWKS(signer.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
		IgnoreIssuer: true, IgnoreAudiences: true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		Type:              jwt.TypeAny, AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.SignClaims(map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := Open(t.Context(), Config{URL: srv.URL, VerificationKeySet: keys})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(compact); err != nil {
		t.Fatalf("initial verification failed: %v", err)
	}
	if got := keyCount(t, keys); got != 1 {
		t.Fatalf("initial keys = %d, want 1", got)
	}
	body.Store([]byte(`{"keys":null}`))
	if err := source.Refresh(t.Context()); err == nil {
		t.Fatal("malformed refresh succeeded")
	}
	if _, err := verifier.Verify(compact); err != nil {
		t.Fatalf("bad refresh discarded the last good verification keys: %v", err)
	}
	body.Store([]byte(`{"keys":[]}`))
	if err := source.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(compact); err == nil {
		t.Fatal("valid empty refresh did not revoke existing verification")
	}
	if got := keyCount(t, keys); got != 0 {
		t.Fatalf("keys after empty refresh = %d, want 0", got)
	}
}

func keyCount(t *testing.T, keys *jwt.VerificationKeySet) int {
	t.Helper()
	data, err := keys.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return len(document.Keys)
}

func TestOpenRejectsNegativeFallbackRefreshInterval(t *testing.T) {
	if _, err := Open(t.Context(), Config{URL: "https://issuer.example/jwks", FallbackRefreshInterval: -1}); err == nil {
		t.Fatal("Open accepted a negative fallback refresh interval")
	}
}

func TestOpenRejectsNegativeRequestTimeout(t *testing.T) {
	if _, err := Open(t.Context(), Config{URL: "https://issuer.example/jwks", RequestTimeout: -1}); err == nil {
		t.Fatal("Open accepted a negative request timeout")
	}
}

func TestRunRefreshesWhenDue(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	refreshed := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 2 {
			close(refreshed)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)
	source, err := Open(t.Context(), Config{URL: srv.URL, FallbackRefreshInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- source.Run(ctx) }()
	select {
	case <-refreshed:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Run did not refresh the JWKS")
	}
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
}

func TestOpenUsesETagAndCacheControl(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	var conditional atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("ETag", `"version-1"`)
		if r.Header.Get("If-None-Match") == `"version-1"` {
			conditional.Store(true)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	source, err := Open(t.Context(), Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	keys := source.VerificationKeySet()
	if err := source.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if source.VerificationKeySet() != keys {
		t.Fatal("304 replaced the stable verification key set handle")
	}
	if !conditional.Load() || hits.Load() != 2 {
		t.Fatalf("conditional fetches: conditional=%v hits=%d", conditional.Load(), hits.Load())
	}
}

func TestKeySetSingleflight(t *testing.T) {
	signer := jwttest.NewSigner(t)
	var hits atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if hits.Load() == 1 {
			close(started)
			<-release
		}
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	}))
	t.Cleanup(srv.Close)

	result := make(chan *Source, 1)
	go func() { source, _ := Open(t.Context(), Config{URL: srv.URL}); result <- source }()
	<-started
	close(release)
	source := <-result
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = source.EnsureFresh(t.Context()) })
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("fetches: got %d, want 1", hits.Load())
	}
}

func TestOpenRejectsInvalidResponses(t *testing.T) {
	for name, body := range map[string][]byte{
		"wrong content type": []byte(`{"keys":[]}`),
		"invalid jwks":       []byte(`{"keys":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "wrong content type" {
					w.Header().Set("Content-Type", "text/plain")
				} else {
					w.Header().Set("Content-Type", "application/json")
				}
				_, _ = w.Write(body)
			}))
			t.Cleanup(srv.Close)
			if _, err := Open(t.Context(), Config{URL: srv.URL}); err == nil {
				t.Fatal("Open accepted invalid response")
			}
		})
	}
}

func TestOpenRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte{' '}, maxJWKSBytes+1))
	}))
	t.Cleanup(srv.Close)
	_, err := Open(t.Context(), Config{URL: srv.URL})
	if err == nil || !errors.Is(err, jwt.ErrSizeLimit) {
		t.Fatalf("error: got %v, want ErrSizeLimit", err)
	}
}

func TestOpenUsesContextHTTPClient(t *testing.T) {
	signer := jwttest.NewSigner(t)
	srv := httptest.NewTLSServer(jwksHandler(nil, signer.JWKS(), ""))
	t.Cleanup(srv.Close)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, srv.Client())
	if _, err := Open(ctx, Config{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
}

func jwksHandler(hits *atomic.Int64, body []byte, cacheControl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}
}
