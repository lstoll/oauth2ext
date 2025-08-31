package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lstoll/oauth2ext/internal"
	"golang.org/x/oauth2"
)

func TestProviderDiscovery(t *testing.T) {
	svr, _ := newMockDiscoveryServer(t)

	if _, err := DiscoverProvider(context.WithValue(t.Context(), oauth2.HTTPClient, svr.Client()), svr.URL); err != nil {
		t.Fatal(err)
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
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(svr.Close)

	p := &Provider{
		Metadata: &ProviderMetadata{
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

func newMockDiscoveryServer(t *testing.T) (*httptest.Server, *internal.TestSigner) {
	testSigner := internal.NewTestSigner(t)

	svr := httptest.NewTLSServer(nil)

	mux := http.NewServeMux()

	pmd := &ProviderMetadata{
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
		w.Header().Set("Content-Type", "application/jwk-set+json")

		if _, err := w.Write(testSigner.JWKS()); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})

	svr.Config.Handler = mux

	return svr, testSigner
}
