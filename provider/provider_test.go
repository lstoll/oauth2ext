package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal/httprevalidate"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwt/remotejwks"
	"lds.li/oauth2ext/jwttest"
)

func TestProviderDiscovery(t *testing.T) {
	svr, signer := newMockDiscoveryServer(t)
	t.Cleanup(svr.Close)

	if _, err := DiscoverOIDCProvider(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), svr.URL); err != nil {
		t.Fatal(err)
	}
	_ = signer
}

func TestDiscoverOIDCProviderRejectsMultipleConfigs(t *testing.T) {
	_, err := DiscoverOIDCProvider(t.Context(), "https://issuer.example", DiscoveryConfig{}, DiscoveryConfig{})
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("error = %v, want multiple-config error", err)
	}
}

func TestDiscoverOIDCProviderRejectsNegativeFallbackRefreshInterval(t *testing.T) {
	_, err := DiscoverOIDCProvider(t.Context(), "https://issuer.example", DiscoveryConfig{FallbackRefreshInterval: -1})
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("error = %v, want negative-interval error", err)
	}
}

func TestDiscoverOIDCProviderRejectsNegativeRequestTimeout(t *testing.T) {
	_, err := DiscoverOIDCProvider(t.Context(), "https://issuer.example", DiscoveryConfig{RequestTimeout: -1})
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("error = %v, want negative-timeout error", err)
	}
}

func TestRefreshAfterPreservesImmediateMetadataDeadline(t *testing.T) {
	signer := jwttest.NewSigner(t)
	client := &http.Client{Transport: roundTripper(func(*http.Request) *http.Response {
		header := make(http.Header)
		header.Set("Content-Type", "application/jwk-set+json")
		header.Set("Cache-Control", "max-age=60")
		return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(string(signer.JWKS())))}
	})}
	source, err := remotejwks.Open(t.Context(), remotejwks.Config{URL: "https://issuer.example/jwks", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{
		metadataResource: httprevalidate.New(httprevalidate.Config{
			URL:                "https://issuer.example/discovery",
			HTTPClient:         client,
			AcceptedMediaTypes: []string{"application/json"},
			MaxBodyBytes:       1024,
		}, 0),
		keyRefresher: source,
	}
	if got := p.refreshAfter(); got != 0 {
		t.Fatalf("refreshAfter = %v, want immediate metadata deadline", got)
	}
}

func TestProviderRefreshForcesDiscoveryAndJWKSRevalidation(t *testing.T) {
	signer := jwttest.NewSigner(t)
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	var discoveryHits, jwksHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		_ = json.NewEncoder(w).Encode(OIDCProviderMetadata{Issuer: server.URL, JWKSURI: server.URL + "/jwks"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksHits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(signer.JWKS())
	})
	server.Config.Handler = mux
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	p, err := DiscoverOIDCProvider(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if discoveryHits.Load() != 2 || jwksHits.Load() != 2 {
		t.Fatalf("hits: discovery=%d jwks=%d, want 2 each", discoveryHits.Load(), jwksHits.Load())
	}
}

func TestProviderRunRefreshesDiscoveryAndJWKSWhenDue(t *testing.T) {
	signer := jwttest.NewSigner(t)
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	var discoveryHits, jwksHits atomic.Int64
	refreshed := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OIDCProviderMetadata{Issuer: server.URL, JWKSURI: server.URL + "/jwks"})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		if jwksHits.Add(1) == 2 && discoveryHits.Load() >= 2 {
			close(refreshed)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	})
	server.Config.Handler = mux
	requestCtx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	p, err := DiscoverOIDCProvider(requestCtx, server.URL, DiscoveryConfig{FallbackRefreshInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(requestCtx)
	errCh := make(chan error, 1)
	go func() { errCh <- p.Run(runCtx) }()
	select {
	case <-refreshed:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Run did not refresh discovery and JWKS")
	}
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context cancellation", err)
	}
}

func TestProviderDiscoveryBindsIssuer(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&OIDCProviderMetadata{
			Issuer:  "https://attacker.example",
			JWKSURI: "https://attacker.example/jwks",
		})
	}))
	t.Cleanup(svr.Close)

	_, err := DiscoverOIDCProvider(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), svr.URL)
	if err == nil || !strings.Contains(err.Error(), "does not match requested issuer") {
		t.Fatalf("error = %v, want issuer mismatch", err)
	}
}

func TestProviderDiscoveryRejectsAmbiguousJSON(t *testing.T) {
	for _, tt := range []struct {
		name string
		body func(string) string
	}{
		{
			name: "duplicate issuer",
			body: func(issuer string) string {
				return fmt.Sprintf(`{"issuer":%q,"issuer":%q,"jwks_uri":%q}`, issuer, issuer, issuer+"/jwks")
			},
		},
		{
			name: "case mismatched issuer",
			body: func(issuer string) string {
				return fmt.Sprintf(`{"Issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/jwks")
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var svr *httptest.Server
			svr = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body(svr.URL)))
			}))
			t.Cleanup(svr.Close)

			_, err := DiscoverOIDCProvider(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), svr.URL)
			if err == nil {
				t.Fatal("expected discovery error")
			}
		})
	}
}

func TestProviderDiscoveryLimitsResponses(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bytes.Repeat([]byte{' '}, maxProviderResponseBytes+1))
	}))
	t.Cleanup(svr.Close)

	_, err := DiscoverOIDCProvider(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), svr.URL)
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("error = %v, want response limit error", err)
	}
}

func TestVerifierDoesNotRefreshForVerificationFailure(t *testing.T) {
	trusted := jwttest.NewSigner(t)
	untrusted := jwttest.NewSigner(t)
	var discoveryRequests atomic.Int64
	var jwksRequests atomic.Int64

	svr := httptest.NewTLSServer(nil)
	t.Cleanup(svr.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryRequests.Add(1)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(&OIDCProviderMetadata{
			Issuer:                           svr.URL,
			JWKSURI:                          svr.URL + "/jwks",
			IDTokenSigningAlgValuesSupported: []string{"ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")
		_, _ = w.Write(trusted.JWKS())
	})
	svr.Config.Handler = mux

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client())
	p, err := DiscoverOIDCProvider(ctx, svr.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw := map[string]any{
		"iss": svr.URL,
		"sub": "subject",
		"aud": "client",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	unknownKeyToken, err := untrusted.SignClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	badSignatureToken, err := trusted.SignClaims(raw)
	if err != nil {
		t.Fatal(err)
	}
	signatureStart := strings.LastIndexByte(badSignatureToken, '.') + 1
	replacement := byte('A')
	if badSignatureToken[signatureStart] == replacement {
		replacement = 'B'
	}
	badSignatureToken = badSignatureToken[:signatureStart] + string(replacement) + badSignatureToken[signatureStart+1:]

	policy := jwt.ValidationPolicy{
		ExpectedAudiences: []string{"client"},
		Type:              jwt.TypeAny,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		RequireIssuedAt:   true,
	}
	for name, compact := range map[string]string{
		"unknown key":   unknownKeyToken,
		"bad signature": badSignatureToken,
	} {
		t.Run(name, func(t *testing.T) {
			verifier, err := p.Verifier(ctx, policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(compact); err == nil {
				t.Fatal("expected verification failure")
			}
		})
	}
	if got := discoveryRequests.Load(); got != 1 {
		t.Fatalf("discovery requests = %d, want 1", got)
	}
	if got := jwksRequests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestJWKSReturnsCopy(t *testing.T) {
	svr, _ := newMockDiscoveryServer(t)
	t.Cleanup(svr.Close)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client())
	p, err := DiscoverOIDCProvider(ctx, svr.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(first)
	first[0] ^= 0xff
	second, err := p.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatal("mutating returned JWKS changed provider cache")
	}
}

func TestDiscoveredProviderUsesVerificationKeyOverride(t *testing.T) {
	local := jwttest.NewSigner(t)
	var discoveryRequests atomic.Int64
	var jwksRequests atomic.Int64

	svr := httptest.NewTLSServer(nil)
	t.Cleanup(svr.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(&OIDCProviderMetadata{
			Issuer:                           svr.URL,
			JWKSURI:                          svr.URL + "/jwks",
			IDTokenSigningAlgValuesSupported: []string{"ES256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		http.Error(w, "must not be fetched", http.StatusInternalServerError)
	})
	svr.Config.Handler = mux

	keys, err := jwt.ParseVerificationJWKS(local.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client())
	p, err := DiscoverOIDCProvider(ctx, svr.URL, DiscoveryConfig{VerificationKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	compact, err := local.SignClaims(map[string]any{
		"iss": svr.URL,
		"sub": "subject",
		"aud": "client",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := jwt.ValidationPolicy{
		ExpectedAudiences: []string{"client"},
		Type:              jwt.TypeAny,
		RequireIssuedAt:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
	}
	verifier, err := p.Verifier(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(compact); err != nil {
		t.Fatal(err)
	}
	verifier, err = p.Verifier(ctx, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(compact); err != nil {
		t.Fatal(err)
	}
	if got := jwksRequests.Load(); got != 0 {
		t.Fatalf("JWKS requests = %d, want 0", got)
	}
	if got := discoveryRequests.Load(); got < 3 {
		t.Fatalf("discovery requests = %d, want at least 3", got)
	}

	first, err := p.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(first)
	first[0] ^= 0xff
	second, err := p.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, want) {
		t.Fatal("mutating returned JWKS changed provider result")
	}
}

func TestUserinfo(t *testing.T) {
	type userinforClaims struct {
		Subject string `json:"sub"`
	}
	wantClaims := &userinforClaims{
		Subject: "test-subject",
	}
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"sub": "test-subject",
			"foo": "bar",
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(svr.Close)

	p := &Provider{
		Metadata: &OIDCProviderMetadata{
			UserinfoEndpoint: svr.URL,
		},
	}

	var gotClaims userinforClaims

	err := p.Userinfo(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), oauth2.StaticTokenSource(&oauth2.Token{}), &gotClaims)
	if err != nil {
		t.Fatal(err)
	}

	// Compare the Subject field
	if wantClaims.Subject != gotClaims.Subject {
		t.Errorf("unexpected subject: want %s, got %s", wantClaims.Subject, gotClaims.Subject)
	}
}

func TestUserinfoRejectsDuplicateClaims(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"first","sub":"second"}`))
	}))
	t.Cleanup(svr.Close)

	p := &Provider{Metadata: &OIDCProviderMetadata{UserinfoEndpoint: svr.URL}}
	var claims map[string]any
	err := p.Userinfo(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), oauth2.StaticTokenSource(&oauth2.Token{}), &claims)
	if err == nil {
		t.Fatal("expected duplicate claim error")
	}
}

func newMockDiscoveryServer(t *testing.T) (*httptest.Server, *jwttest.Signer) {
	testSigner := jwttest.NewSigner(t)

	svr := httptest.NewTLSServer(nil)

	mux := http.NewServeMux()

	pmd := &OIDCProviderMetadata{
		Issuer:                           svr.URL,
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		JWKSURI:                          svr.URL + "/.well-known/jwks.json",
	}

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(pmd); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")

		if _, err := w.Write(testSigner.JWKS()); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})

	svr.Config.Handler = mux

	return svr, testSigner
}

type roundTripper func(*http.Request) *http.Response

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r), nil
}
