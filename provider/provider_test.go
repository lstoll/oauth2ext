package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
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

func TestVerifyJWTDoesNotRefreshForVerificationFailure(t *testing.T) {
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
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		RequireIssuedAt:   true,
	}
	for name, compact := range map[string]string{
		"unknown key":   unknownKeyToken,
		"bad signature": badSignatureToken,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.VerifyJWT(ctx, compact, policy); err == nil {
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

	keys, err := jwt.ParseVerificationKeySet(local.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client())
	p, err := DiscoverOIDCProvider(ctx, svr.URL, WithVerificationKeys(keys))
	if err != nil {
		t.Fatal(err)
	}
	p.CacheDuration = -1 // Force metadata refreshes during verification.

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
		RequireIssuedAt:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
	}
	if _, err := p.VerifyJWT(ctx, compact, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyJWT(ctx, compact, policy); err != nil {
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

func TestWithVerificationKeysRejectsNil(t *testing.T) {
	if _, err := DiscoverOIDCProvider(t.Context(), "https://issuer.example", WithVerificationKeys(nil)); err == nil {
		t.Fatal("expected nil verification key source error")
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
