package tokencache

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
)

// testStore is an in-memory Store with software DPoP keys.
type testStore struct {
	creds   map[string]*Credential
	created int
}

func newTestStore() *testStore { return &testStore{creds: map[string]*Credential{}} }

func (s *testStore) Get(issuer, key string) (*Credential, error) { return s.creds[issuer+";"+key], nil }

func (s *testStore) Set(issuer, key string, cred *Credential) error {
	s.creds[issuer+";"+key] = cred
	return nil
}

func (s *testStore) Available() bool { return true }

func (s *testStore) NewDPoPKey() ([]byte, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	handle, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	s.created++
	return handle, key, nil
}

func (s *testStore) LoadDPoPKey(handle []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(handle)
	if err != nil {
		return nil, err
	}
	return key.(crypto.Signer), nil
}

func (s *testStore) thumbprint(t *testing.T, handle []byte) string {
	t.Helper()
	key, err := s.LoadDPoPKey(handle)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return signer.Thumbprint()
}

// fakeDPoPSource returns tokens of the given type, recording the signer used.
type fakeDPoPSource struct {
	tokenType string
	signers   []*jwt.SigningIdentity
	bearer    int
}

func (f *fakeDPoPSource) Token() (*oauth2.Token, error) {
	f.bearer++
	return &oauth2.Token{AccessToken: "bearer", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}, nil
}

func (f *fakeDPoPSource) DPoPToken(signer *jwt.SigningIdentity) (*oauth2.Token, error) {
	f.signers = append(f.signers, signer)
	return &oauth2.Token{AccessToken: "new", RefreshToken: "refresh", TokenType: f.tokenType, Expiry: time.Now().Add(time.Hour)}, nil
}

func TestDPoPNewTokenStoresKey(t *testing.T) {
	store := newTestStore()
	source := &fakeDPoPSource{tokenType: "DPoP"}
	ts, err := (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tok, signer, err := ts.DPoPToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "new" || signer == nil || len(source.signers) != 1 || source.signers[0] != signer {
		t.Fatalf("unexpected token %+v, signer %v, source signers %v", tok, signer, source.signers)
	}
	cred := store.creds["iss;k"]
	if cred == nil || cred.DPoPKey == nil {
		t.Fatalf("credential not stored with its key: %+v", cred)
	}
	if got := store.thumbprint(t, cred.DPoPKey); got != signer.Thumbprint() {
		t.Fatalf("stored key thumbprint %s, signer %s", got, signer.Thumbprint())
	}

	// A cached hit returns the same key without creating another.
	_, again, err := ts.DPoPToken()
	if err != nil {
		t.Fatal(err)
	}
	if again.Thumbprint() != signer.Thumbprint() || store.created != 1 || len(source.signers) != 1 {
		t.Fatalf("cache hit changed the key or refetched: created=%d fetches=%d", store.created, len(source.signers))
	}
}

func TestDPoPRejectsBearerToken(t *testing.T) {
	store := newTestStore()
	source := &fakeDPoPSource{tokenType: "Bearer"}
	ts, err := (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Token(); err == nil || !strings.Contains(err.Error(), "DPoP") {
		t.Fatalf("want DPoP error, got %v", err)
	}
	if len(store.creds) != 0 {
		t.Fatal("bearer token was cached")
	}
}

func TestDPoPIgnoresMismatchedEntries(t *testing.T) {
	store := newTestStore()
	valid := &oauth2.Token{AccessToken: "cached", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}

	// A bearer entry is not returned when DPoP is enabled.
	store.creds["iss;k"] = &Credential{Token: valid}
	source := &fakeDPoPSource{tokenType: "DPoP"}
	ts, err := (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(); err != nil || tok.AccessToken != "new" {
		t.Fatalf("bearer entry used for DPoP: %+v, %v", tok, err)
	}

	// A DPoP entry is not returned when DPoP is disabled.
	ts, err = (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(); err != nil || tok.AccessToken != "bearer" {
		t.Fatalf("DPoP entry used without DPoP: %+v, %v", tok, err)
	}

	// An entry whose key can't be loaded is a miss.
	store.creds["iss;k"] = &Credential{Token: valid, DPoPKey: []byte("garbage")}
	ts, err = (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(); err != nil || tok.AccessToken != "new" {
		t.Fatalf("entry with unloadable key used: %+v, %v", tok, err)
	}
}

func TestDPoPRefreshUsesStoredKey(t *testing.T) {
	store := newTestStore()
	handle, _, err := store.NewDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	wantThumb := store.thumbprint(t, handle)

	var proofThumb string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, err := (&dpop.Verifier{}).VerifyAndDecode(r.Header.Get("DPoP"), mustValidator(t, &dpop.ValidatorOpts{IgnoreThumbprint: true}))
		if err != nil {
			t.Errorf("refresh proof: %v", err)
			http.Error(w, "bad proof", http.StatusBadRequest)
			return
		}
		proofThumb = proof.Thumbprint
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed", "refresh_token": "refresh-2", "token_type": "DPoP", "expires_in": 3600})
	}))
	t.Cleanup(server.Close)

	store.creds["iss;k"] = &Credential{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh-1", TokenType: "DPoP", Expiry: time.Now().Add(-time.Minute)},
		DPoPKey: handle,
	}
	source := &fakeDPoPSource{tokenType: "DPoP"}
	ts, err := (&Config{
		Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store,
		TokenSourceProvider: &oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tok, signer, err := ts.DPoPToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "refreshed" || len(source.signers) != 0 || store.created != 1 {
		t.Fatalf("refresh not used: token %+v, fetches %d, keys created %d", tok, len(source.signers), store.created)
	}
	if proofThumb != wantThumb || signer.Thumbprint() != wantThumb {
		t.Fatalf("refresh proof key %s, returned key %s, want stored key %s", proofThumb, signer.Thumbprint(), wantThumb)
	}
	if got := store.creds["iss;k"]; got.Token.RefreshToken != "refresh-2" || string(got.DPoPKey) != string(handle) {
		t.Fatalf("refreshed credential not stored with the same key: %+v", got)
	}
}

func TestDPoPClient(t *testing.T) {
	store := newTestStore()
	source := &fakeDPoPSource{tokenType: "DPoP"}
	ts, err := (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, signer, err := ts.DPoPToken()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "DPoP new" {
			t.Errorf("Authorization = %q", got)
		}
		_, err := (&dpop.Verifier{}).VerifyAndDecode(r.Header.Get("DPoP"), mustValidator(t, &dpop.ValidatorOpts{
			ExpectedThumbprint:  signer.Thumbprint(),
			ExpectedAccessToken: "new",
		}))
		if err != nil {
			t.Errorf("resource proof: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	resp, err := ts.Client(nil).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestDPoPRequiresDPoPSource(t *testing.T) {
	store := newTestStore()
	_, err := (&Config{Issuer: "iss", CacheKey: "k", WrappedSource: &mockTokenSource{}, Cache: store, DPoPKeys: store}).TokenSource(t.Context())
	if err == nil || !strings.Contains(err.Error(), "DPoPTokenSource") {
		t.Fatalf("want DPoPTokenSource error, got %v", err)
	}
}

func mustValidator(t *testing.T, opts *dpop.ValidatorOpts) *dpop.Validator {
	t.Helper()
	v, err := dpop.NewValidator(opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSwitchingDPoPModeReplacesEntry(t *testing.T) {
	store := newTestStore()
	source := &fakeDPoPSource{tokenType: "DPoP"}
	dpopCfg := &Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store, DPoPKeys: store}
	bearerCfg := &Config{Issuer: "iss", CacheKey: "k", WrappedSource: source, Cache: store}

	for _, cfg := range []*Config{dpopCfg, bearerCfg, dpopCfg, bearerCfg} {
		ts, err := cfg.TokenSource(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if len(source.signers) != 2 || source.bearer != 2 {
		t.Fatalf("got %d DPoP fetches and %d bearer fetches, want each mode switch to fetch a new token", len(source.signers), source.bearer)
	}
}

func TestRefreshFailureIsLogged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(server.Close)

	store := newTestStore()
	store.creds["iss;k"] = &Credential{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "r", Expiry: time.Now().Add(-time.Minute)}}
	var logs strings.Builder
	ts, err := (&Config{
		Issuer: "iss", CacheKey: "k", WrappedSource: &fakeDPoPSource{}, Cache: store,
		TokenSourceProvider: &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		Logger:              slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}).TokenSource(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := ts.Token(); err != nil || tok.AccessToken != "bearer" {
		t.Fatalf("want fallback token, got %+v, %v", tok, err)
	}
	if !strings.Contains(logs.String(), "refreshing cached token failed") || !strings.Contains(logs.String(), "invalid_grant") {
		t.Fatalf("refresh failure not logged: %s", logs.String())
	}
}
