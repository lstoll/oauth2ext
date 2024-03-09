package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lstoll/oidc"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

// mockOIDCServer mocks out just enough of an OIDC server for tests. It accepts
// validClientID, validClientSecret and validRedirectURL as parameters, and
// returns an ID token with claims upon success.
type mockOIDCServer struct {
	baseURL           string
	validClientID     string
	validClientSecret string
	validRedirectURL  string
	claims            map[string]interface{}

	keyset *keyset.Handle

	mux *http.ServeMux
}

func startServer(t *testing.T, handler http.Handler) (baseURL string, cleanup func()) {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	baseURL = fmt.Sprintf("http://localhost:%s", port)
	server := &http.Server{
		Handler: handler,
	}

	go func() { _ = server.Serve(l) }()

	return baseURL, func() {
		_ = server.Shutdown(context.Background())
		_ = l.Close()
	}
}

func startMockOIDCServer(t *testing.T) (server *mockOIDCServer, cleanup func()) {
	t.Helper()

	server = newMockOIDCServer()
	baseURL, cleanup := startServer(t, server)
	server.baseURL = baseURL

	return server, cleanup
}

func newMockOIDCServer() *mockOIDCServer {
	s := &mockOIDCServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /auth", s.handleAuth)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /keys", s.handleKeys)
	s.mux = mux

	// Very short key. Used only for testing so generation time is quick.
	s.keyset = mustGenHandle()

	return s
}

func (s *mockOIDCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *mockOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := oidc.ProviderMetadata{
		Issuer:                        s.baseURL,
		AuthorizationEndpoint:         fmt.Sprintf("%s/auth", s.baseURL),
		TokenEndpoint:                 fmt.Sprintf("%s/token", s.baseURL),
		JWKSURI:                       fmt.Sprintf("%s/keys", s.baseURL),
		ResponseTypesSupported:        []string{"code"},
		CodeChallengeMethodsSupported: []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
	}

	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *mockOIDCServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID != s.validClientID {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI != s.validRedirectURL {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	responseType := r.URL.Query().Get("response_type")
	if responseType != "code" {
		http.Error(w, "invalid response_type", http.StatusBadRequest)
		return
	}

	scope := r.URL.Query().Get("scope")
	if !strings.Contains(scope, "openid") {
		http.Error(w, "invalid scope", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", s.validRedirectURL, url.QueryEscape("valid-code"), url.QueryEscape(state))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *mockOIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	} else if clientID != s.validClientID || clientSecret != s.validClientSecret {
		http.Error(w, "invalid client ID or client secret", http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	if code != "valid-code" {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		// TODO: Support refreshes
		http.Error(w, "invalid grant_type", http.StatusUnauthorized)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if redirectURI != s.validRedirectURL {
		http.Error(w, "invalid redirect_uri", http.StatusUnauthorized)
		return
	}

	signer, err := jwt.NewSigner(s.keyset)
	if err != nil {
		slog.Error("failed to create signer", "err", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	now := time.Now()
	sub, _ := s.claims["sub"].(string)
	rJWTopts := &jwt.RawJWTOptions{
		Subject:      &sub,
		Issuer:       &s.baseURL,
		Audience:     &clientID,
		ExpiresAt:    ptr(now.Add(time.Minute)),
		IssuedAt:     &now,
		CustomClaims: map[string]any{},
	}
	for k, v := range s.claims {
		if k == "sub" { // we extract this earlier
			continue
		}
		rJWTopts.CustomClaims[k] = v
	}
	rawJWT, err := jwt.NewRawJWT(rJWTopts)
	if err != nil {
		slog.Error("failed to create raw JWT", "err", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	idToken, err := signer.SignAndEncode(rawJWT)
	if err != nil {
		slog.Error("failed to sign and encode", "err", err.Error())
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	resp := struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
	}{
		AccessToken: "abc123",
		TokenType:   "Bearer",
		IDToken:     idToken,
	}

	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *mockOIDCServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	ph, err := s.keyset.Public()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jwksb, err := jwt.JWKSetFromPublicKeysetHandle(ph)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(jwksb); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func TestMiddleware_HappyPath(t *testing.T) {
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf("sub: %s", ClaimsFromContext(r.Context()).Subject)))
	})

	oidcServer, cleanupOIDCServer := startMockOIDCServer(t)
	defer cleanupOIDCServer()

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"

	store, err := NewMemorySessionStore(http.Cookie{Name: "oidc-login", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}

	handler := &Handler{
		Issuer:       oidcServer.baseURL,
		ClientID:     oidcServer.validClientID,
		ClientSecret: oidcServer.validClientSecret,
		SessionStore: store,
	}

	baseURL, cleanupServer := startServer(t, handler.Wrap(protected))
	defer cleanupServer()

	handler.BaseURL = baseURL

	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", baseURL)
	oidcServer.claims = map[string]interface{}{"sub": "valid-subject"}
	handler.RedirectURL = oidcServer.validRedirectURL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Get(baseURL)
	if err != nil {
		t.Fatal(err)
	}

	body := checkResponse(t, resp)
	if !bytes.Equal([]byte("sub: valid-subject"), body) {
		t.Fatalf("wanted body %s, got %s", "sub: valid-subject", string(body))
	}
}

func TestContext(t *testing.T) {
	var ( // Capture in handler
		gotTokSrc oauth2.TokenSource
		gotClaims *oidc.IDClaims
		gotRaw    string
	)
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTokSrc = TokenSourceFromContext(r.Context())
		gotClaims = ClaimsFromContext(r.Context())
		gotRaw = RawIDTokenFromContext(r.Context())
	})

	oidcServer, cleanupOIDCServer := startMockOIDCServer(t)
	defer cleanupOIDCServer()

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"

	store, err := NewMemorySessionStore(http.Cookie{Name: "oidc-login", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}

	handler := &Handler{
		Issuer:       oidcServer.baseURL,
		ClientID:     oidcServer.validClientID,
		ClientSecret: oidcServer.validClientSecret,
		SessionStore: store,
	}

	baseURL, cleanupServer := startServer(t, handler.Wrap(protected))
	defer cleanupServer()

	handler.BaseURL = baseURL

	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", baseURL)
	oidcServer.claims = map[string]interface{}{"sub": "valid-subject"}
	handler.RedirectURL = oidcServer.validRedirectURL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	if _, err = client.Get(baseURL); err != nil {
		t.Fatal(err)
	}

	if gotClaims.Subject != "valid-subject" {
		t.Errorf("want claims sub valid-subject, got: %s", gotClaims.Subject)
	}
	if gotRaw == "" {
		t.Error("context missing id_token")
	}

	_, err = gotTokSrc.Token()
	if err != nil {
		t.Fatalf("calling token source token: %v", err)
	}
}

func checkResponse(t *testing.T, resp *http.Response) (body []byte) {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("bad response: HTTP %d: %s", resp.StatusCode, body)
	}

	return body
}

func mustGenHandle() *keyset.Handle {
	h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		panic(err)
	}

	return h
}

func ptr[T any](v T) *T {
	return &v
}
