package oauth2as

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	"github.com/google/uuid"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as/internal"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
	"lds.li/oauth2ext/oauth2as/internal/token"
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

		es256ClientID       = "es256-client"
		es256ClientSecret   = "es256-secret"
		es256ClientRedirect = "https://es256"
	)

	newOIDC := func() *Server {
		s := NewMemStorage()

		return &Server{
			config: Config{
				Issuer: issuer,

				Storage: s,
				Signer:  testSigner(t),

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
						ID:           es256ClientID,
						Secrets:      []string{es256ClientSecret},
						RedirectURLs: []string{es256ClientRedirect},
						Opts:         []ClientOpt{ClientOptSkipPKCE(), ClientOptSigningAlg(jwt.SigningAlgES256)},
					},
				},
			},

			now: time.Now,
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}
	})

	t.Run("Redeeming an already redeemed code should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.codeToken(context.Background(), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// replay fails
		_, err = o.codeToken(context.Background(), treq)
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
			t.Errorf("want invalid token grant error, got: %v", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.codeToken(context.Background(), treq)
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Client secret that differs from the original client should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2.TokenRequest{
			GrantType:   oauth2.GrantTypeAuthorizationCode,
			Code:        codeToken,
			RedirectURI: redirectURI,
			// This is not the credentials the code should be tracking, but are
			// otherwise valid
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
		}

		_, err := o.codeToken(context.Background(), treq)
		if err, ok := err.(*oauth2.TokenError); !ok || err.ErrorCode != oauth2.TokenErrorCodeUnauthorizedClient {
			t.Errorf("want unauthorized client error, got: %v", err)
		}
	})

	t.Run("Response access token validity time honoured", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
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

		tresp, err := o.codeToken(context.Background(), treq)
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
		newToken := token.New(tokenUsageAuthCode)

		// Create a StoredGrant with the auth code
		grant := &StoredGrant{
			ID:            uuid.New(),
			UserID:        "testsub",
			ClientID:      es256ClientID,
			GrantedScopes: []string{oidc.ScopeOfflineAccess},
			AuthCode:      newToken.Stored(),
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(1 * time.Minute),
		}

		if err := o.config.Storage.CreateGrant(context.Background(), grant); err != nil {
			t.Fatal(err)
		}

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         newToken.User(),
			RedirectURI:  redirectURI,
			ClientID:     es256ClientID,
			ClientSecret: es256ClientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), treq)
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

		var headerMap map[string]interface{}
		if err := json.Unmarshal(header, &headerMap); err != nil {
			t.Fatalf("failed to unmarshal id_token header: %v", err)
		}

		alg, ok := headerMap["alg"].(string)
		if !ok {
			t.Fatalf("alg not found in id_token header")
		}

		if alg != "ES256" {
			t.Fatalf("want alg to be ES256, got: %s", alg)
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

		return &Server{

			config: Config{
				Issuer: issuer,

				Storage: s,
				Signer:  testSigner(t),

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

				AuthValidityTime: 1 * time.Minute,
				CodeValidityTime: 1 * time.Minute,
				MaxRefreshTime:   6 * time.Hour,
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
			treq := &oauth2.TokenRequest{
				GrantType:    oauth2.GrantTypeRefreshToken,
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			tresp, err := o.refreshToken(context.Background(), treq)
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

		// march to the future, when we should be expired
		o.now = func() time.Time { return time.Now().Add(1 * time.Hour) }

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.refreshToken(context.Background(), treq)
		if te, ok := err.(*oauth2.TokenError); !ok || te.ErrorCode != oauth2.TokenErrorCodeInvalidGrant {
			t.Errorf("expired session should have given invalid_grant, got: %v", te)
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

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.refreshToken(context.Background(), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		terr, ok := err.(*oauth2.TokenError)
		if !ok {
			t.Fatalf("want token error, got: %T", err)
		}
		if terr.ErrorCode != oauth2.TokenErrorCodeInvalidGrant || terr.Description != errDesc {
			t.Fatalf("unexpected code %q (want %q) or description %q (want %q)", terr.ErrorCode, oauth2.TokenErrorCodeInvalidGrant, terr.Description, errDesc)
		}

		// refresh with generic err
		refreshToken = newRefreshGrant(t, o.config.Storage)

		returnErr = errors.New("boomtown")

		treq = &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.refreshToken(context.Background(), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		if _, ok = err.(*oauth2.HTTPError); !ok {
			t.Fatalf("want http error, got %T (%v)", err, err)
		}
	})

}

func TestUserinfo(t *testing.T) {
	echoHandler := func(w io.Writer, uireq *UserinfoRequest) error {
		o := map[string]interface{}{
			"gotsub": uireq.Subject,
		}

		if err := json.NewEncoder(w).Encode(o); err != nil {
			t.Fatal(err)
		}

		return nil
	}

	signAccessToken := func(cl jwt.AccessTokenClaims) string {
		sat, err := testSigner(t).(*internal.TestSigner).SignClaimsWithAlgorithm("ES256", jwt.JWTTYPAccessToken, cl)
		if err != nil {
			t.Fatal(err)
		}

		return sat
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
		WantJSON map[string]interface{}
	}{
		{
			Name: "Simple output, valid session",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(jwt.AccessTokenClaims{
					Issuer:  issuer,
					Subject: "sub",
					Expiry:  jwt.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				})
			},
			Handler: echoHandler,
			WantJSON: map[string]interface{}{
				"gotsub": "sub",
			},
		},
		{
			Name: "Token for other issuer",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(jwt.AccessTokenClaims{
					Issuer:  "http://other",
					Subject: "sub",
					Expiry:  jwt.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				})
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "Expired access token",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(jwt.AccessTokenClaims{
					Issuer:  issuer,
					Subject: "sub",
					Expiry:  jwt.UnixTime(time.Now().Add(-1 * time.Minute).Unix()),
				})
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

			config := Config{
				Issuer:  issuer,
				Storage: s,
				Signer:  testSigner(t),
				UserinfoHandler: func(_ context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error) {
					return &UserinfoResponse{
						Identity: &jwt.IDClaims{
							Issuer:  issuer,
							Subject: uireq.Subject,
							Expiry:  jwt.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
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

var (
	signer     *internal.TestSigner
	signerOnce sync.Once
)

func testSigner(t *testing.T) AlgorithmSigner {
	signerOnce.Do(func() {
		signer = internal.NewTestSigner(t, "RS256", "ES256")
	})
	return signer
}

func newRefreshGrant(t *testing.T, smgr Storage) (refreshToken string) {
	newToken := token.New(tokenUsageRefresh)
	refreshToken = newToken.User()

	// Create a StoredGrant with the refresh token
	grant := &StoredGrant{
		ID:            uuid.New(),
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		RefreshToken:  newToken.Stored(),
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(60 * time.Minute),
	}

	if err := smgr.CreateGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}

	return refreshToken
}

func newCodeGrant(t *testing.T, smgr Storage) (authCode string) {
	newToken := token.New(tokenUsageAuthCode)
	code := newToken.User()

	// Create a StoredGrant with the auth code
	grant := &StoredGrant{
		ID:            uuid.New(),
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		AuthCode:      newToken.Stored(),
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Minute),
	}

	if err := smgr.CreateGrant(context.Background(), grant); err != nil {
		t.Fatal(err)
	}

	return code
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
			return sc.Opts, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}
