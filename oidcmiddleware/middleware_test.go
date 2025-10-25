package oidcmiddleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/oidc"
)

// mockOIDCServer mocks out just enough of an OIDC server for tests. It accepts
// validClientID, validClientSecret and validRedirectURL as parameters, and
// returns an ID token with claims upon success.
type mockOIDCServer struct {
	baseURL           string
	validClientID     string
	validClientSecret string
	validRedirectURL  string
	claimOptions      *jwt.RawJWTOptions

	signer *internal.TestSigner

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
	s := &mockOIDCServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /auth", s.handleAuth)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /keys", s.handleKeys)
	s.mux = mux

	s.signer = internal.NewTestSigner(t)

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

	clOpts := *s.claimOptions
	clOpts.Issuer = &s.baseURL
	clOpts.Audience = &clientID
	clOpts.ExpiresAt = ptr(time.Now().Add(time.Minute))
	clOpts.IssuedAt = ptr(time.Now())

	cl, err := jwt.NewRawJWT(&clOpts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawJWT, err := s.signer.Sign(cl)
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
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idt, ok := IDClaimsFromContext(r.Context())
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

	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claimOptions = &jwt.RawJWTOptions{
		Subject: ptr("valid-subject"),
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, nil, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}

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
		wg.Add(1)
		go func() {
			defer wg.Done()

			resp, err := client.Get(httpServer.URL)
			if err != nil {
				errC <- err
			}
			respC <- resp
		}()
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

func TestContext(t *testing.T) {
	var ( // Capture in handler
		gotIDClaims *jwt.VerifiedJWT
	)
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idclaims, ok := IDClaimsFromContext(r.Context())
		if !ok {
			t.Log("handler: no ID token in context")
			http.Error(w, "no ID token in context", http.StatusInternalServerError)
			return
		}
		gotIDClaims = idclaims
	})

	oidcServer, oidcHTTPServer := startMockOIDCServer(t)

	httpServer := httptest.NewTLSServer(nil)
	t.Cleanup(httpServer.Close)

	oidcServer.validClientID = "valid-client-id"
	oidcServer.validClientSecret = "valid-client-secret"
	oidcServer.validRedirectURL = fmt.Sprintf("%s/callback", httpServer.URL)
	oidcServer.claimOptions = &jwt.RawJWTOptions{
		Subject: ptr("valid-subject"),
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, oidcHTTPServer.Client())
	handler, err := NewFromDiscovery(ctx, nil, oidcServer.baseURL, oidcServer.validClientID, oidcServer.validClientSecret, oidcServer.validRedirectURL)
	if err != nil {
		t.Fatal(err)
	}

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

func ptr[T any](v T) *T {
	return &v
}
