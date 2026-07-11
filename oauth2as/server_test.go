package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as/internal/token"
	"lds.li/oauth2ext/oauth2as/oauth2proto"
	"lds.li/oauth2ext/oidc"
)

type unauthorizedErrImpl struct{ error }

func (u *unauthorizedErrImpl) Unauthorized() bool { return true }

func TestCodeToken(t *testing.T) {
	const (
		issuer = "https://issuer"

		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"

		otherClientID       = "other-client"
		otherClientSecret   = "other-secret"
		otherClientRedirect = "https://other"

		rs256ClientID       = "rs256-client"
		rs256ClientSecret   = "rs256-secret"
		rs256ClientRedirect = "https://rs256"
	)

	newOIDC := func() *Server {
		s := NewMemStorage()

		signer, verifier := testSignerVerifier(t)

		return &Server{
			config: Config{
				Issuer: issuer,

				Storage:  s,
				Signer:   signer,
				Verifier: verifier,

				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},

				Clients: staticClientSource{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURLs: []string{redirectURI},
						Opts:         []ClientOpt{ClientOptSkipPKCE()},
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURLs: []string{otherClientRedirect},
						Opts:         []ClientOpt{ClientOptSkipPKCE()},
					},
					{
						ID:           rs256ClientID,
						Secrets:      []string{rs256ClientSecret},
						RedirectURLs: []string{rs256ClientRedirect},
						Opts:         []ClientOpt{ClientOptSkipPKCE(), ClientOptIDTokenSigningAlgorithm(jwt.RS256)},
					},
				},
			},

			now: time.Now,
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}
		if _, ok := tresp.ExtraParams["id_token"]; ok {
			t.Error("token response included an ID token without the openid scope")
		}
	})

	t.Run("Redeeming an already redeemed code should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// replay fails
		_, err = o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
			t.Errorf("want invalid token grant error, got: %v", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Client secret that differs from the original client should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:   oauth2proto.GrantTypeAuthorizationCode,
			Code:        codeToken,
			RedirectURI: redirectURI,
			// This is not the credentials the code should be tracking, but are
			// otherwise valid
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Response access token validity time honoured", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{
				IDTokenExpiry:     time.Now().Add(5 * time.Minute),
				AccessTokenExpiry: time.Now().Add(5 * time.Minute),
			}, nil
		}

		tresp, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}

		// compare whole seconds, we calculate this based on a expiresAt - now
		// delta so the function run time is factored in.
		if tresp.ExpiresIn > 5*time.Minute+2*time.Second || tresp.ExpiresIn < 5*time.Minute-2*time.Second {
			t.Errorf("want token exp within 2s of %f, got: %f", 5*time.Minute.Seconds(), tresp.ExpiresIn.Seconds())
		}
	})

	t.Run("Should issue different tokens for different algorithms", func(t *testing.T) {
		o := newOIDC()

		// Create a StoredGrant with the auth code
		grant := &StoredGrant{
			UserID:        "testsub",
			ClientID:      rs256ClientID,
			GrantedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(1 * time.Minute),
			Request: &AuthRequest{
				ClientID:    rs256ClientID,
				RedirectURI: rs256ClientRedirect,
				State:       "",
				Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			},
		}

		grantID, err := o.config.Storage.CreateGrant(context.Background(), grant)
		if err != nil {
			t.Fatal(err)
		}

		authCodeID := newUUIDv4()
		newToken, err := token.New(tokenUsageAuthCode, authCodeID, grantID, grant.UserID)
		if err != nil {
			t.Fatal(err)
		}

		// Create token entry for the auth code
		err = o.config.Storage.CreateAuthCode(context.Background(), authCodeID, &StoredAuthCode{
			Code:             newToken.Stored(),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(1 * time.Minute),
			StorageExpiresAt: time.Now().Add(1 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		authCodeStr := newToken.UserToken()

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         authCodeStr,
			RedirectURI:  rs256ClientRedirect,
			ClientID:     rs256ClientID,
			ClientSecret: rs256ClientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		idt, ok := tresp.ExtraParams["id_token"].(string)
		if !ok {
			t.Fatalf("id_token not found in extra params")
		}

		parts := strings.Split(idt, ".")
		if len(parts) != 3 {
			t.Fatalf("id_token should have 3 parts, got: %v", parts)
		}

		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("failed to decode id_token header: %v", err)
		}

		var headerMap map[string]any
		if err := json.Unmarshal(header, &headerMap); err != nil {
			t.Fatalf("failed to unmarshal id_token header: %v", err)
		}

		alg, ok := headerMap["alg"].(string)
		if !ok {
			t.Fatalf("alg not found in id_token header")
		}

		if alg != "RS256" {
			t.Fatalf("want ID token alg to be RS256, got: %s", alg)
		}

		parts = strings.Split(tresp.AccessToken, ".")
		if len(parts) != 3 {
			t.Fatalf("access token should have 3 parts, got: %v", parts)
		}
		header, err = base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("failed to decode access token header: %v", err)
		}
		if err := json.Unmarshal(header, &headerMap); err != nil {
			t.Fatalf("failed to unmarshal access token header: %v", err)
		}
		if alg, _ := headerMap["alg"].(string); alg != "ES256" {
			t.Fatalf("want access token alg to remain ES256, got: %q", alg)
		}
	})

}

func TestRefreshToken(t *testing.T) {
	const (
		issuer = "https://issuer"

		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"

		otherClientID       = "other-client"
		otherClientSecret   = "other-secret"
		otherClientRedirect = "https://other"
	)

	newOIDC := func() *Server {
		s := NewMemStorage()

		signer, verifier := testSignerVerifier(t)

		return &Server{

			config: Config{
				Issuer: issuer,

				Storage:  s,
				Signer:   signer,
				Verifier: verifier,

				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},
				Clients: staticClientSource{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURLs: []string{redirectURI},
						Opts:         []ClientOpt{ClientOptSkipPKCE()},
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURLs: []string{otherClientRedirect},
						Opts:         []ClientOpt{ClientOptSkipPKCE()},
					},
				},

				CodeValidityTime:     1 * time.Minute,
				RefreshTokenValidity: 6 * time.Hour,
				GrantValidity:        6 * time.Hour,
			},

			now: time.Now,
		}
	}

	t.Run("Refresh token happy path", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{}, nil
		}

		// keep trying to refresh
		for i := 1; i <= 5; i++ {
			treq := &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			tresp, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
			if err != nil {
				t.Fatalf("iter %d: unexpected error calling token with refresh token: %v", i, err)
			}

			if tresp.AccessToken == "" {
				t.Errorf("iter %d: refresh request should have returned an access token, but got none", i)
			}

			if tresp.RefreshToken == "" {
				t.Errorf("iter %d: refresh request should have returned a refresh token, but got none", i)
			}

			refreshToken = tresp.RefreshToken
		}

		// try again while we still should be within the expiry period.
		o.now = func() time.Time { return time.Now().Add(5 * time.Hour) }

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("failed to refresh token while still in validity period: %v", err)
		}
		refreshToken = tresp.RefreshToken
		if refreshToken == "" {
			t.Fatal("refresh request should have returned a refresh token, but got none")
		}

		// march to the future, when we should be expired
		o.now = func() time.Time { return time.Now().Add(7 * time.Hour) }

		treq = &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if te, ok := err.(*oauth2proto.TokenError); !ok || te.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
			t.Errorf("expired session should have given invalid_grant, got: %v", te)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized_client error, got: %v", err)
		}
	})

	t.Run("Refresh token with handler errors", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		var returnErr error
		const errDesc = "Refresh unauthorized"

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			if returnErr != nil {
				return nil, returnErr
			}
			return &TokenResponse{
				// OverrideRefreshTokenExpiry: o.now().Add(10 * time.Minute),
			}, nil
		}

		// try and refresh, and observe intentional unauth error
		returnErr = &unauthorizedErrImpl{error: errors.New(errDesc)}

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		terr, ok := err.(*oauth2proto.TokenError)
		if !ok {
			t.Fatalf("want token error, got: %T", err)
		}
		if terr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant || terr.Description != errDesc {
			t.Fatalf("unexpected code %q (want %q) or description %q (want %q)", terr.ErrorCode, oauth2proto.TokenErrorCodeInvalidGrant, terr.Description, errDesc)
		}

		// refresh with generic err
		refreshToken = newRefreshGrant(t, o.config.Storage)

		returnErr = errors.New("boomtown")

		treq = &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		if _, ok = err.(*oauth2proto.HTTPError); !ok {
			t.Fatalf("want http error, got %T (%v)", err, err)
		}
	})

}

func TestUserinfo(t *testing.T) {
	echoHandler := func(w io.Writer, uireq *UserinfoRequest) error {
		o := map[string]any{
			"gotsub": uireq.Subject,
		}

		if err := json.NewEncoder(w).Encode(o); err != nil {
			t.Fatal(err)
		}

		return nil
	}

	signAccessToken := func(tokenIssuer string, expiresAt time.Time) string {
		signer, _ := testSignerVerifier(t)
		payload, err := jsonv2.Marshal(map[string]any{
			"iss": tokenIssuer,
			"sub": "sub",
			"iat": time.Now().Unix(),
			"exp": expiresAt.Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		compact, err := signer.SignJWT(t.Context(), jwt.ES256, JWTSigningInput{Type: "at+jwt", Payload: payload})
		if err != nil {
			t.Fatal(err)
		}

		return compact
	}

	issuer := "http://iss"

	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and an access
		// token
		Setup   func(t *testing.T) (accessToken string)
		Handler func(w io.Writer, uireq *UserinfoRequest) error
		// WantErr signifies that we expect an error
		WantErr bool
		// WantJSON is what we want the endpoint to return
		WantJSON map[string]any
	}{
		{
			Name: "Simple output, valid session",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(issuer, time.Now().Add(time.Minute))
			},
			Handler: echoHandler,
			WantJSON: map[string]any{
				"gotsub": "sub",
			},
		},
		{
			Name: "Token for other issuer",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken("http://other", time.Now().Add(time.Minute))
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "Expired access token",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(issuer, time.Now().Add(-time.Minute))
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "No access token",
			Setup: func(t *testing.T) (accessToken string) {
				return ""
			},
			Handler: echoHandler,
			WantErr: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			s := NewMemStorage()

			signer, verifier := testSignerVerifier(t)

			config := Config{
				Issuer:   issuer,
				Storage:  s,
				Signer:   signer,
				Verifier: verifier,
				UserinfoHandler: func(_ context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error) {
					return &UserinfoResponse{
						Identity: map[string]any{
							"iss": issuer,
							"sub": uireq.Subject,
							"exp": time.Now().Add(1 * time.Minute).Unix(),
						},
					}, nil
				},
				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},
				Clients: staticClientSource{},
				Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
			}

			oidc, err := NewServer(config)
			if err != nil {
				t.Fatal(err)
			}

			at := tc.Setup(t)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/userinfo", nil)

			if at != "" {
				req.Header.Set("authorization", "Bearer "+at)
			}

			oidc.UserinfoHandler(rec, req)
			if tc.WantErr && rec.Result().StatusCode == http.StatusOK {
				t.Error("want error, but got none")
			}
			if !tc.WantErr && rec.Result().StatusCode != http.StatusOK {
				t.Errorf("want no error, got status: %d", rec.Result().StatusCode)
			}
		})
	}
}

func TestUserinfoGrantContext(t *testing.T) {
	const issuer = "http://iss"

	s := NewMemStorage()
	grant := &StoredGrant{
		UserID:        "sub",
		ClientID:      "client-id",
		GrantedScopes: []string{"openid", "profile"},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		Metadata:      []byte(`{"federation":"abc"}`),
		ACR:           "urn:mace:incommon:iap:silver",
		AMR:           []string{"pwd"},
	}
	grantID, err := s.CreateGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	signer, verifier := testSignerVerifier(t)
	input, err := marshalSigningInput("at+jwt", map[string]any{
		"iss":        issuer,
		"sub":        "sub",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(time.Minute).Unix(),
		claimGrantID: grantID,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := signer.SignJWT(t.Context(), jwt.ES256, input)
	if err != nil {
		t.Fatal(err)
	}

	var gotReq *UserinfoRequest
	oidc, err := NewServer(Config{
		Issuer:   issuer,
		Storage:  s,
		Signer:   signer,
		Verifier: verifier,
		UserinfoHandler: func(_ context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error) {
			gotReq = uireq
			return &UserinfoResponse{Identity: map[string]any{"sub": uireq.Subject}}, nil
		},
		TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{}, nil
		},
		Clients: staticClientSource{},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("authorization", "Bearer "+accessToken)
	oidc.UserinfoHandler(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("want status 200, got %d", rec.Result().StatusCode)
	}
	if gotReq == nil {
		t.Fatal("userinfo handler was not called")
	}
	if gotReq.GrantID != grantID {
		t.Errorf("GrantID: want %q, got %q", grantID, gotReq.GrantID)
	}
	if string(gotReq.Metadata) != `{"federation":"abc"}` {
		t.Errorf("Metadata: got %q", gotReq.Metadata)
	}
	if !slices.Equal(gotReq.GrantedScopes, []string{"openid", "profile"}) {
		t.Errorf("GrantedScopes: got %v", gotReq.GrantedScopes)
	}
	if gotReq.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR: got %q", gotReq.ACR)
	}
	if !slices.Equal(gotReq.AMR, []string{"pwd"}) {
		t.Errorf("AMR: got %v", gotReq.AMR)
	}

	gotReq.Metadata[0] = 'X'
	gotReq.GrantedScopes[0] = "changed"
	gotReq.AMR[0] = "changed"
	stored, err := s.GetGrant(t.Context(), grantID)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.Metadata) != `{"federation":"abc"}` || !slices.Equal(stored.GrantedScopes, []string{"openid", "profile"}) || !slices.Equal(stored.AMR, []string{"pwd"}) {
		t.Fatalf("userinfo handler mutated stored grant: %#v", stored)
	}
}

func TestValidateTokenClientAllowsPublicClientWithoutSecret(t *testing.T) {
	server := &Server{config: Config{Clients: staticClientSource{{ID: "public", Public: true}}}}
	err := server.validateTokenClient(t.Context(), &oauth2proto.TokenRequest{ClientID: "public"}, "public")
	if err != nil {
		t.Fatal(err)
	}
}

var (
	signer     *LocalJWTSigner
	signerOnce sync.Once
)

func testSignerVerifier(t *testing.T) (JWTSigner, JWTVerifier) {
	signerOnce.Do(func() {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer, err = NewLocalJWTSigner(LocalJWTSignerConfig{SigningKeys: []SigningKey{
			{Algorithm: jwt.ES256, Key: ecKey},
			{Algorithm: jwt.RS256, Key: rsaKey},
		}})
		if err != nil {
			t.Fatal(err)
		}
	})
	return signer, signer
}

func newRefreshGrant(t *testing.T, smgr Storage) (refreshToken string) {
	// Create a StoredGrant with the refresh token
	grant := &StoredGrant{
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(6 * time.Hour),
	}

	grantID, err := smgr.CreateGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	refreshTokenID := newUUIDv4()
	newToken, err := token.New(tokenUsageRefresh, refreshTokenID, grantID, grant.UserID)
	if err != nil {
		t.Fatal(err)
	}

	// Create token entry for the refresh token
	err = smgr.CreateRefreshToken(context.Background(), refreshTokenID, &StoredRefreshToken{
		Token:            newToken.Stored(),
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(6 * time.Hour),
		StorageExpiresAt: time.Now().Add(6 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	return newToken.UserToken()
}

func newCodeGrant(t *testing.T, smgr Storage) (authCode string) {
	// Create a StoredGrant with the auth code
	grant := &StoredGrant{
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Minute),
		Request: &AuthRequest{
			ClientID:    "client-id",
			RedirectURI: "https://redirect",
			State:       "",
			Scopes:      []string{oidc.ScopeOfflineAccess},
		},
	}

	grantID, err := smgr.CreateGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	authCodeID := newUUIDv4()
	newToken, err := token.New(tokenUsageAuthCode, authCodeID, grantID, grant.UserID)
	if err != nil {
		t.Fatal(err)
	}

	// Create token entry for the auth code
	err = smgr.CreateAuthCode(context.Background(), authCodeID, &StoredAuthCode{
		Code:             newToken.Stored(),
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(1 * time.Minute),
		StorageExpiresAt: time.Now().Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	return newToken.UserToken()
}

type staticClient struct {
	ID           string
	Secrets      []string
	RedirectURLs []string
	Public       bool
	Opts         []ClientOpt
}

type staticClientSource []staticClient

func (c staticClientSource) IsValidClientID(ctx context.Context, clientID string) (ok bool, err error) {
	return slices.ContainsFunc(c, func(sc staticClient) bool {
		return sc.ID == clientID
	}), nil
}

func (c staticClientSource) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) (ok bool, err error) {
	return slices.ContainsFunc(c, func(sc staticClient) bool {
		return sc.ID == clientID && slices.Contains(sc.Secrets, clientSecret)
	}), nil
}

func (c staticClientSource) ClientSecrets(ctx context.Context, clientID string) ([]string, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			return sc.Secrets, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}

func (c staticClientSource) RedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			return sc.RedirectURLs, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}

func (c staticClientSource) ClientOpts(ctx context.Context, clientID string) ([]ClientOpt, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			opts := slices.Clone(sc.Opts)
			if sc.Public {
				opts = append(opts, ClientOptPublic())
			}
			return opts, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}
