package clientjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

func TestTokenSourceExchangeAndRefresh(t *testing.T) {
	signer, keys := testSignerAndKeys(t)
	var exchanges, refreshes int
	var tokenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Errorf("method: got %s", req.Method)
		}
		if req.Header.Get("Authorization") != "" {
			t.Error("Authorization header set")
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.Form.Get("client_secret") != "" {
			t.Error("client_secret sent")
		}
		if req.Form.Get("client_id") != "client" {
			t.Errorf("client_id: got %q", req.Form.Get("client_id"))
		}
		if req.Form.Get("client_assertion_type") != AssertionType {
			t.Errorf("assertion type: got %q", req.Form.Get("client_assertion_type"))
		}
		assertion := req.Form.Get("client_assertion")
		verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
			ExpectedIssuer:    "client",
			ExpectedAudiences: []string{tokenURL},
			AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
			Type:              jwt.TypeJWTOrAbsent,
			RequireIssuedAt:   true,
			ClockSkew:         jwt.DefaultClockSkew,
		})
		if err == nil {
			_, err = verifier.Verify(assertion)
		}
		if err != nil {
			t.Errorf("verify assertion: %v", err)
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch req.Form.Get("grant_type") {
		case "authorization_code":
			exchanges++
			if req.Form.Get("code") != "the-code" {
				t.Errorf("code: got %q", req.Form.Get("code"))
			}
			if req.Form.Get("code_verifier") != "pkce" {
				t.Errorf("code_verifier: got %q", req.Form.Get("code_verifier"))
			}
			writeToken(w, "access-1", "refresh-1", 1)
		case "refresh_token":
			refreshes++
			if req.Form.Get("refresh_token") != "refresh-1" {
				t.Errorf("refresh_token: got %q", req.Form.Get("refresh_token"))
			}
			writeToken(w, "access-2", "refresh-2", 3600)
		default:
			t.Errorf("grant_type: got %q", req.Form.Get("grant_type"))
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	tokenURL = server.URL

	cfg := &Config{
		ClientID:         "client",
		Endpoint:         oauth2.Endpoint{TokenURL: server.URL},
		RedirectURL:      "https://client.example/callback",
		Signer:           signer,
		SigningAlgorithm: jwt.ES256,
		HTTPClient:       server.Client(),
	}
	tok, err := cfg.Exchange(t.Context(), "the-code", oauth2.SetAuthURLParam("code_verifier", "pkce"))
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" || tok.RefreshToken != "refresh-1" {
		t.Fatalf("exchange token: %+v", tok)
	}

	tok.Expiry = time.Now().Add(-time.Second)
	got, err := cfg.TokenSource(t.Context(), tok).Token()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "access-2" || got.RefreshToken != "refresh-2" {
		t.Fatalf("refresh token: %+v", got)
	}
	if exchanges != 1 || refreshes != 1 {
		t.Fatalf("exchanges=%d refreshes=%d", exchanges, refreshes)
	}
}

func TestTokenEndpointRedirectDoesNotLeakAssertion(t *testing.T) {
	var leaked int
	leakServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		leaked++
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(leakServer.Close)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, leakServer.URL, http.StatusFound)
	}))
	t.Cleanup(tokenServer.Close)
	signer, _ := testSignerAndKeys(t)
	cfg := &Config{
		ClientID:         "client",
		Endpoint:         oauth2.Endpoint{TokenURL: tokenServer.URL},
		Signer:           signer,
		SigningAlgorithm: jwt.ES256,
		HTTPClient:       tokenServer.Client(),
	}
	if _, err := cfg.Exchange(t.Context(), "code"); err == nil {
		t.Fatal("redirect response unexpectedly returned a token")
	}
	if leaked != 0 {
		t.Fatalf("token endpoint redirect was followed %d times", leaked)
	}
}

func TestAssertionAudienceOverride(t *testing.T) {
	signer, keys := testSignerAndKeys(t)
	const audience = "https://auth.example/"
	var tokenURL string
	var assertions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
			ExpectedIssuer: "client", ExpectedAudiences: []string{audience},
			AllowedAlgorithms: []jwt.Algorithm{jwt.ES256}, Type: jwt.TypeJWTOrAbsent,
			RequireIssuedAt: true, ClockSkew: jwt.DefaultClockSkew,
		})
		assertion := req.Form.Get("client_assertion")
		var verified *jwt.VerifiedJWT
		if err == nil {
			verified, err = verifier.Verify(assertion)
		}
		if err != nil {
			t.Errorf("verify audience override: %v", err)
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		jti, err := verified.JWTID()
		if err != nil {
			t.Errorf("assertion jti: %v", err)
			return
		}
		assertions = append(assertions, jti)
		switch req.Form.Get("grant_type") {
		case "authorization_code":
			writeToken(w, "access-1", "refresh-1", 3600)
		case "refresh_token":
			if req.Form.Get("refresh_token") != "refresh-1" {
				t.Errorf("refresh token: got %q", req.Form.Get("refresh_token"))
			}
			writeToken(w, "access-2", "refresh-2", 3600)
		default:
			t.Errorf("grant_type: got %q", req.Form.Get("grant_type"))
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	tokenURL = server.URL
	cfg := &Config{
		ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: tokenURL},
		Signer: signer, SigningAlgorithm: jwt.ES256, AssertionAudience: audience,
		HTTPClient: server.Client(),
	}
	tok, err := cfg.Exchange(t.Context(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" || tok.RefreshToken != "refresh-1" {
		t.Fatalf("exchange token: %+v", tok)
	}
	tok.Expiry = time.Now().Add(-time.Second)
	refreshed, err := cfg.TokenSource(t.Context(), tok).Token()
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "access-2" || refreshed.RefreshToken != "refresh-2" {
		t.Fatalf("refreshed token: %+v", refreshed)
	}
	if len(assertions) != 2 || assertions[0] == assertions[1] {
		t.Fatalf("assertions did not use fresh jti values: %v", assertions)
	}
}

func TestCertificateThumbprintConfigUsesHeaderAndRejectsMissingCertificate(t *testing.T) {
	signer, keys, cert := certificateSignerAndKeys(t)
	var requests int
	var tokenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if err := req.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		assertion := req.Form.Get("client_assertion")
		verifier, err := jwt.NewVerifier(keys, jwt.ValidationPolicy{
			ExpectedIssuer: "client", ExpectedAudiences: []string{tokenURL},
			AllowedAlgorithms: []jwt.Algorithm{jwt.ES256}, Type: jwt.TypeJWTOrAbsent,
			RequireIssuedAt: true,
		})
		if err == nil {
			_, err = verifier.Verify(assertion)
		}
		if err != nil {
			t.Errorf("verify certificate assertion: %v", err)
			http.Error(w, "invalid assertion", http.StatusUnauthorized)
			return
		}
		headerBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(assertion, ".")[0])
		if err != nil {
			t.Error(err)
			return
		}
		var header map[string]any
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			t.Error(err)
			return
		}
		thumb := sha256.Sum256(cert.Raw)
		if got, want := header["x5t#S256"], base64.RawURLEncoding.EncodeToString(thumb[:]); got != want {
			t.Errorf("x5t#S256: got %v, want %q", got, want)
		}
		if header["kid"] != "client-key" {
			t.Errorf("kid: got %v", header["kid"])
		}
		writeToken(w, "access", "", 3600)
	}))
	t.Cleanup(server.Close)
	tokenURL = server.URL
	config := func(identity jwt.Signer, includeThumbprint bool) *Config {
		return &Config{
			ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL},
			Signer: identity, SigningAlgorithm: jwt.ES256,
			CertificateThumbprint: includeThumbprint, HTTPClient: server.Client(),
		}
	}
	if _, err := config(signer, true).Exchange(t.Context(), "code"); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("token requests: got %d, want 1", requests)
	}
	missingCertSigner, _ := testSignerAndKeys(t)
	if _, err := config(missingCertSigner, true).Exchange(t.Context(), "code"); err == nil {
		t.Fatal("exchange unexpectedly succeeded without certificate")
	}
	if requests != 1 {
		t.Fatalf("missing-certificate failure reached endpoint: requests=%d", requests)
	}
}

func TestInvalidConfigTokenSourceAndClientFailWithoutPanic(t *testing.T) {
	var nilConfig *Config
	if _, err := nilConfig.TokenSource(t.Context(), nil).Token(); err == nil {
		t.Fatal("nil config token source unexpectedly succeeded")
	}
	client := nilConfig.Client(t.Context(), nil)
	if _, err := client.Get("https://example.invalid/"); err == nil {
		t.Fatal("nil config client unexpectedly succeeded")
	}

	invalid := new(Config)
	if _, err := invalid.TokenSource(t.Context(), nil).Token(); err == nil {
		t.Fatal("invalid config token source unexpectedly succeeded")
	}
	if _, err := invalid.Client(t.Context(), nil).Get("https://example.invalid/"); err == nil {
		t.Fatal("invalid config client unexpectedly succeeded")
	}
}

func writeToken(w http.ResponseWriter, access, refresh string, expiresIn int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"refresh_token": refresh,
		"expires_in":    expiresIn,
	})
}
