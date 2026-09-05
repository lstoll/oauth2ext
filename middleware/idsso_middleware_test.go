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
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/jwttest"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
)

type rejectingIDTokenVerifier struct {
	calls int
}

type memorySessionStore struct {
	session *SessionData
	saves   int
}

func (s *memorySessionStore) GetOIDCSession(*http.Request) (*SessionData, error) {
	return s.session, nil
}

func (s *memorySessionStore) SaveOIDCSession(http.ResponseWriter, *http.Request, *SessionData) error {
	s.saves++
	return nil
}

func (v *rejectingIDTokenVerifier) Verify(context.Context, string, claims.IDTokenValidationInput) (struct{}, error) {
	return struct{}{}, errors.New("rejected")
}

func (v *rejectingIDTokenVerifier) VerifyTokenResponse(context.Context, *oauth2.Token, claims.IDTokenValidationInput) (struct{}, error) {
	v.calls++
	return struct{}{}, errors.New("rejected")
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

func TestStartAuthenticationPublicClientRequiresPKCES256(t *testing.T) {
	h := &IDSSOHandler[struct{}]{
		OAuth2Config: &oauth2.Config{ClientID: "public-client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth"}},
		Provider:     &provider.Provider{Metadata: &provider.OIDCProviderMetadata{}},
	}
	if _, err := h.startAuthentication(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), &SessionData{}); err == nil {
		t.Fatal("public client started without provider PKCE S256 support")
	}
}

func TestStartAuthenticationConfidentialClientRequiresExplicitPKCEOptOut(t *testing.T) {
	h := &IDSSOHandler[struct{}]{
		OAuth2Config: &oauth2.Config{ClientID: "confidential-client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth"}},
		Provider:     &provider.Provider{Metadata: &provider.OIDCProviderMetadata{}},
	}
	if _, err := h.startAuthentication(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), &SessionData{}); err == nil {
		t.Fatal("confidential client started without provider PKCE S256 support or an explicit opt-out")
	}
	h.DisablePKCE = true
	if _, err := h.startAuthentication(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), &SessionData{}); err != nil {
		t.Fatalf("confidential client explicit PKCE opt-out failed: %v", err)
	}
}

func TestStartAuthenticationUsesPKCEWithoutDiscovery(t *testing.T) {
	h := &IDSSOHandler[struct{}]{
		OAuth2Config: &oauth2.Config{ClientID: "public-client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth"}},
	}
	session := &SessionData{}
	authURL, err := h.startAuthentication(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), session)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("authorization URL did not enable S256 PKCE: %s", authURL)
	}
	if len(session.Logins) != 1 || session.Logins[0].PKCEChallenge == "" {
		t.Fatal("login state did not retain the PKCE verifier")
	}
}

func TestStartAuthenticationCannotDisablePKCEForPublicClient(t *testing.T) {
	h := &IDSSOHandler[struct{}]{
		OAuth2Config: &oauth2.Config{ClientID: "public-client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/auth"}},
		DisablePKCE:  true,
	}
	if _, err := h.startAuthentication(httptest.NewRequest(http.MethodGet, "https://rp.example/", nil), &SessionData{}); err == nil {
		t.Fatal("public client disabled PKCE")
	}
}

func TestAuthenticateCallbackRejectsAndConsumesExpiredLogin(t *testing.T) {
	h := &IDSSOHandler[struct{}]{}
	session := &SessionData{Logins: []SessionDataLogin{{State: "expired-state", Expires: int(time.Now().Add(-time.Minute).Unix())}}}
	r := httptest.NewRequest(http.MethodGet, "https://rp.example/callback?state=expired-state&code=code", nil)
	if _, err := h.authenticateCallback(r, session); err == nil {
		t.Fatal("expired login state was accepted")
	}
	if len(session.Logins) != 0 {
		t.Fatalf("expired login state was not consumed: %#v", session.Logins)
	}
}

func TestAuthenticateCallbackPublicClientRejectsMissingPKCE(t *testing.T) {
	h := &IDSSOHandler[struct{}]{
		OAuth2Config: &oauth2.Config{ClientID: "public-client"},
	}
	session := &SessionData{Logins: []SessionDataLogin{{
		State:   "state-without-pkce",
		Expires: int(time.Now().Add(time.Minute).Unix()),
	}}}
	r := httptest.NewRequest(http.MethodGet, "https://rp.example/callback?state=state-without-pkce&code=code", nil)
	if _, err := h.authenticateCallback(r, session); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("missing PKCE verifier error = %v", err)
	}
	if len(session.Logins) != 0 {
		t.Fatalf("invalid login state was not consumed: %#v", session.Logins)
	}
}

func TestWrapPersistsConsumedExpiredLogin(t *testing.T) {
	store := &memorySessionStore{session: &SessionData{Logins: []SessionDataLogin{{
		State:   "expired-state",
		Expires: int(time.Now().Add(-time.Minute).Unix()),
	}}}}
	h := &IDSSOHandler[struct{}]{
		Verifier:     &rejectingIDTokenVerifier{},
		SessionStore: store,
	}
	r := httptest.NewRequest(http.MethodGet, "https://rp.example/callback?state=expired-state&code=code", nil)
	w := httptest.NewRecorder()
	h.Wrap(http.NotFoundHandler()).ServeHTTP(w, r)
	if store.saves != 1 {
		t.Fatalf("SaveOIDCSession calls = %d, want 1", store.saves)
	}
	if len(store.session.Logins) != 0 {
		t.Fatalf("expired login state was not persisted as consumed: %#v", store.session.Logins)
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
