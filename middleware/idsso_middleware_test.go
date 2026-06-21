package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/jwttest"
	"lds.li/oauth2ext/oidc"
)

type rejectingIDTokenVerifier struct {
	calls int
}

func (v *rejectingIDTokenVerifier) Verify(context.Context, string, claims.IDTokenValidationInput) (struct{}, error) {
	return struct{}{}, errors.New("rejected")
}

func (v *rejectingIDTokenVerifier) VerifyTokenResponse(context.Context, *oauth2.Token, claims.IDTokenValidationInput) (struct{}, error) {
	v.calls++
	return struct{}{}, errors.New("rejected")
}

type unusedIDVerifier struct{}

func (unusedIDVerifier) Verify(context.Context, string, claims.IDTokenValidationInput) (*claims.VerifiedID, error) {
	return nil, errors.New("unused")
}

func (unusedIDVerifier) VerifyTokenResponse(context.Context, *oauth2.Token, claims.IDTokenValidationInput) (*claims.VerifiedID, error) {
	return nil, errors.New("unused")
}

// mockOIDCServer mocks out just enough of an OIDC server for tests. It accepts
// validClientID, validClientSecret and validRedirectURL as parameters, and
// returns an ID token with claims upon success.
type mockOIDCServer struct {
	baseURL           string
	validClientID     string
	validClientSecret string
	validRedirectURL  string
	claims            map[string]any
	nonces            sync.Map

	signer *jwttest.Signer

	mux *http.ServeMux
}

func startMockOIDCServer(t *testing.T) (server *mockOIDCServer, httpServer *httptest.Server) {
	server = newMockOIDCServer(t)
	httpServer = httptest.NewTLSServer(server)
	t.Cleanup(httpServer.Close)

	server.baseURL = httpServer.URL

	return server, httpServer
}

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
	t.Helper()
	s := &mockOIDCServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /auth", s.handleAuth)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /keys", s.handleKeys)
	s.mux = mux

	s.signer = jwttest.NewSigner(t)

	return s
}

func (s *mockOIDCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *mockOIDCServer) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := oidc.ProviderMetadata{
		Issuer:                           s.baseURL,
		AuthorizationEndpoint:            fmt.Sprintf("%s/auth", s.baseURL),
		TokenEndpoint:                    fmt.Sprintf("%s/token", s.baseURL),
		JWKSURI:                          fmt.Sprintf("%s/keys", s.baseURL),
		ResponseTypesSupported:           []string{"code"},
		CodeChallengeMethodsSupported:    []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
	}

	w.Header().Add("Content-Type", "application/json")
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
	code := "valid-code:" + state
	s.nonces.Store(code, r.URL.Query().Get("nonce"))
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", s.validRedirectURL, url.QueryEscape(code), url.QueryEscape(state))
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
	nonceValue, ok := s.nonces.LoadAndDelete(code)
	if !ok {
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

	claims := maps.Clone(s.claims)
	if claims == nil {
		claims = make(map[string]any)
	}
	claims["iss"] = s.baseURL
	claims["aud"] = clientID
	claims["exp"] = time.Now().Add(time.Minute).Unix()
	claims["iat"] = time.Now().Unix()
	claims["nonce"] = nonceValue.(string)

	rawJWT, err := s.signer.SignClaims(claims)
	if err != nil {
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
		IDToken:     rawJWT,
	}

	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *mockOIDCServer) handleKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/jwk-set+json")

	if _, err := w.Write(s.signer.JWKS()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func TestMiddleware_HappyPath(t *testing.T) {
	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claims = map[string]any{
		"sub": "valid-subject",
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, nil, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idt, ok := handler.IDClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no ID token in context", http.StatusInternalServerError)
			return
		}
		sub, err := idt.Subject()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(fmt.Appendf(nil, "sub: %s", sub))
	})

	httpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO - do we want a better way to do this, or should this basically
		// be the solution? It's the oauth2 client way I guess...
		r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidcHTTPServer.Client()))
		handler.Wrap(protected).ServeHTTP(w, r)
	})

	// handler.BaseURL = httpServer.URL

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := httpServer.Client()
	client.Jar = jar

	// we run a bunch of concurrent iterations, to make sure that state mismatch
	// etc. doesn't happen
	var (
		flowIters = 10
		wg        sync.WaitGroup
		respC     = make(chan *http.Response, flowIters)
		errC      = make(chan error, flowIters)
	)
	for i := 1; i <= flowIters; i++ {
		wg.Go(func() {

			resp, err := client.Get(httpServer.URL)
			if err != nil {
				errC <- err
			}
			respC <- resp
		})
	}
	wg.Wait()
	close(errC)
	close(respC)

	for err := range errC {
		t.Errorf("error in request: %v", err)
	}
	if len(respC) == 0 {
		t.Fatal("no responses on channel")
	}
	for resp := range respC {
		body := checkResponse(t, resp)
		if !bytes.Equal([]byte("sub: valid-subject"), body) {
			t.Errorf("wanted body %s, got %s", "sub: valid-subject", string(body))
		}
	}
}

func TestAuthenticateExistingDoesNotRetryVerificationFailure(t *testing.T) {
	verifier := new(rejectingIDTokenVerifier)
	h := &IDSSOHandler[struct{}]{
		Verifier: verifier,
		OAuth2Config: &oauth2.Config{
			ClientID: "client-id",
		},
	}
	session := &SessionData{Token: &oidc.TokenWithID{Token: &oauth2.Token{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}}}

	token, _ := h.authenticateExisting(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), session)
	if token != nil {
		t.Fatal("verification failure returned a token")
	}
	if verifier.calls != 1 {
		t.Fatalf("verification calls: got %d, want 1", verifier.calls)
	}
}

func TestContext(t *testing.T) {
	var (
		gotIDClaims *claims.VerifiedID
	)

	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claims = map[string]any{
		"sub": "valid-subject",
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, nil, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idclaims, ok := handler.IDClaimsFromContext(r.Context())
		if !ok {
			t.Log("handler: no ID token in context")
			http.Error(w, "no ID token in context", http.StatusInternalServerError)
			return
		}
		gotIDClaims = idclaims
	})

	httpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO - do we want a better way to do this, or should this basically
		// be the solution? It's the oauth2 client way I guess...
		r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidcHTTPServer.Client()))
		handler.Wrap(protected).ServeHTTP(w, r)
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := httpServer.Client()
	client.Jar = jar

	if _, err = client.Get(httpServer.URL); err != nil {
		t.Fatal(err)
	}

	if gotIDClaims == nil {
		t.Fatal("no ID claims in context")
	}

	gotSub, err := gotIDClaims.Subject()
	if err != nil {
		t.Fatal(err)
	}

	if gotSub != "valid-subject" {
		t.Errorf("want jwt sub valid-subject, got: %s", gotSub)
	}
}

type memSessStore struct {
	mu sync.Mutex
	s  *SessionData
}

func (m *memSessStore) GetOIDCSession(r *http.Request) (*SessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := SessionData{}
	if m.s != nil {
		out.Token = m.s.Token
		if m.s.Logins != nil {
			out.Logins = slices.Clone(m.s.Logins)
		}
	}
	return &out, nil
}

func (m *memSessStore) SaveOIDCSession(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d == nil {
		m.s = nil
		return nil
	}
	cp := *d
	if d.Logins != nil {
		cp.Logins = slices.Clone(d.Logins)
	}
	m.s = &cp
	return nil
}

func TestServeLogout_clearsSessionAndRedirects(t *testing.T) {
	store := &memSessStore{}
	store.mu.Lock()
	store.s = &SessionData{
		Logins: []SessionDataLogin{{State: "pending", Expires: int(time.Now().Add(time.Hour).Unix())}},
	}
	store.mu.Unlock()

	h := IDSSOHandler[*claims.VerifiedID]{
		SessionStore: store,
		Verifier:     unusedIDVerifier{},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	h.ServeLogout(rr, req, "")

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.s == nil {
		t.Fatal("nil session after logout")
	}
	if store.s.Token != nil || len(store.s.Logins) != 0 {
		t.Fatalf("want cleared session, got token=%v logins=%d", store.s.Token, len(store.s.Logins))
	}
}

func TestServeLogout_redirectExplicitReturnTo(t *testing.T) {
	store := &memSessStore{}
	h := IDSSOHandler[*claims.VerifiedID]{
		SessionStore: store,
		Verifier:     unusedIDVerifier{},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	h.ServeLogout(rr, req, "/goodbye")

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("code %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/goodbye" {
		t.Fatalf("Location = %q", got)
	}
}

func TestMiddleware_AllowUnauthenticated(t *testing.T) {
	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claims = map[string]any{
		"sub": "valid-subject",
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, &memSessStore{}, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	handler.AllowUnauthenticated = true

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := handler.IDClaimsFromContext(r.Context()); ok {
			http.Error(w, "unexpected claims", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("anonymous"))
	})

	httpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidcHTTPServer.Client()))
		handler.Wrap(protected).ServeHTTP(w, r)
	})

	client := httpServer.Client()
	resp, err := client.Get(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if string(body) != "anonymous" {
		t.Fatalf("body = %q, want anonymous", body)
	}
}

func TestMiddleware_AJAXUnauth401(t *testing.T) {
	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claims = map[string]any{
		"sub": "valid-subject",
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, &memSessStore{}, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	handler.AJAXUnauth401 = true

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidcHTTPServer.Client()))
		handler.Wrap(protected).ServeHTTP(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("Location = %q, want empty", got)
	}
}

func TestServeLogin_storesReturnToAndRedirects(t *testing.T) {
	oidcServer, oidcHTTPServer := startMockOIDCServer(t)
	store := &memSessStore{}

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claims = map[string]any{
		"sub": "valid-subject",
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, store, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req = req.WithContext(context.WithValue(req.Context(), oauth2.HTTPClient, oidcHTTPServer.Client()))
	handler.ServeLogin(rr, req, "/after")

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, oidcServer.baseURL+"/auth") {
		t.Fatalf("Location = %q", loc)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.s == nil || len(store.s.Logins) != 1 {
		t.Fatalf("logins = %v", store.s)
	}
	if got := store.s.Logins[0].ReturnTo; got != "/after" {
		t.Fatalf("ReturnTo = %q", got)
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
