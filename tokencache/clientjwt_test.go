package tokencache

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clientjwt"
	"lds.li/oauth2ext/jwt"
)

func TestClientJWTExchangeThenCacheRefresh(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, jwt.ES256, "")
	if err != nil {
		t.Fatal(err)
	}
	var exchanges, refreshes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("client_assertion") == "" || r.Form.Get("client_assertion_type") == "" {
			t.Error("clientjwt assertion missing from token request")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			exchanges++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "first", "refresh_token": "refresh-1", "expires_in": 3600})
		case "refresh_token":
			refreshes++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "second", "refresh_token": "refresh-2", "expires_in": 3600})
		default:
			t.Errorf("unexpected grant type %q", r.Form.Get("grant_type"))
			http.Error(w, "unexpected grant", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client := &clientjwt.Config{
		ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL},
		Signer: signer, SigningAlgorithm: jwt.ES256,
	}

	tok, err := client.Exchange(t.Context(), "code")
	if err != nil {
		t.Fatal(err)
	}
	tok.Expiry = time.Now().Add(-time.Second)
	cache := &memCache{cache: map[string]oauth2.Token{"issuerclient": *tok}}
	wrapped := &staticTokenSource{token: "fallback"}
	cfg := Config{
		Issuer: "issuer", CacheKey: "client", WrappedSource: wrapped,
		TokenSourceProvider: client, Cache: cache,
	}
	ts, err := cfg.TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "second" || got.RefreshToken != "refresh-2" {
		t.Fatalf("cached refresh returned %+v", got)
	}
	if exchanges != 1 || refreshes != 1 {
		t.Fatalf("token requests: exchange=%d refresh=%d, want 1 each", exchanges, refreshes)
	}
}
