package oidcop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidcop/internal/oauth2"
	corev1 "github.com/lstoll/oidcop/proto/core/v1"
	"github.com/lstoll/oidcop/staticclients"
	"github.com/lstoll/oidcop/storage"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

var _ AuthHandlers = (*authFnHandlers)(nil)

type authFnHandlers struct {
	authorizer         Authorizer
	startAuthorization func(w http.ResponseWriter, req *http.Request, authReq *AuthorizationRequest)
	token              func(req *TokenRequest) (*TokenResponse, error)
	refreshToken       func(req *RefreshTokenRequest) (*TokenResponse, error)
	userinfo           func(w io.Writer, uireq *UserinfoRequest) (*UserinfoResponse, error)
}

func (a *authFnHandlers) SetAuthorizer(at Authorizer) { a.authorizer = at }
func (a *authFnHandlers) StartAuthorization(w http.ResponseWriter, req *http.Request, authReq *AuthorizationRequest) {
	a.startAuthorization(w, req, authReq)
}
func (a *authFnHandlers) Token(req *TokenRequest) (*TokenResponse, error) { return a.token(req) }
func (a *authFnHandlers) RefreshToken(req *RefreshTokenRequest) (*TokenResponse, error) {
	return a.refreshToken(req)
}
func (a *authFnHandlers) Userinfo(w io.Writer, uireq *UserinfoRequest) (*UserinfoResponse, error) {
	return a.userinfo(w, uireq)
}

func TestStartAuthorization(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"
	)

	clientSource := &staticclients.Clients{
		Clients: []staticclients.Client{
			{
				ID:           clientID,
				Secrets:      []string{clientSecret},
				RedirectURLs: []string{redirectURI},
			},
		},
	}

	for _, tc := range []struct {
		Name             string
		Query            url.Values
		WantHTTPStatus   int
		CheckHTTPReponse func(*testing.T, *httptest.ResponseRecorder)
		CheckResponse    func(*testing.T, storage.Storage, *AuthorizationRequest)
	}{
		{
			Name: "Bad client ID should return error directly",
			Query: url.Values{
				"client_id":     []string{"bad-client"},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
			},
			WantHTTPStatus: 400,
		},
		{
			Name: "Bad redirect URI should return error directly",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{"https://wrong"},
			},
			WantHTTPStatus: 400,
		},
		{
			Name: "Valid request is parsed correctly",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
			},
			CheckResponse: func(t *testing.T, s storage.Storage, areq *AuthorizationRequest) {
				if len(areq.ACRValues) > 0 {
					t.Errorf("want 0 acr_values, got: %d", len(areq.ACRValues))
				}

				ar, err := s.GetAuthRequest(context.Background(), areq.ID)
				if err != nil {
					t.Fatal(err)
				}
				if ar == nil {
					t.Error("session should not be nil")
				}
			},
		},
		{
			Name: "ACR values correctly parsed",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"code"},
				"redirect_uri":  []string{redirectURI},
				"acr_values":    []string{"mfa smfa"},
			},
			CheckResponse: func(t *testing.T, _ storage.Storage, areq *AuthorizationRequest) {
				if len(areq.ACRValues) != 2 {
					t.Errorf("want 2 acr_values, got: %d", len(areq.ACRValues))
				}
				if diff := cmp.Diff([]string{"mfa", "smfa"}, areq.ACRValues); diff != "" {
					t.Error(diff)
				}
			},
		},
		{
			Name: "Implicit flow fails",
			Query: url.Values{
				"client_id":     []string{clientID},
				"response_type": []string{"token"},
				"redirect_uri":  []string{redirectURI},
			},
			CheckHTTPReponse: func(t *testing.T, rr *httptest.ResponseRecorder) {
				predir, err := url.Parse(rr.Result().Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if qerr := predir.Query().Get("error"); qerr != string(oauth2.AuthErrorCodeUnsupportedResponseType) {
					t.Fatalf("want err on redir %s, got: %s", oauth2.AuthErrorCodeUnsupportedResponseType, qerr)
				}
			},
			WantHTTPStatus: 302,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
			if err != nil {
				t.Fatal(err)
			}

			oidc := &OIDC{
				clients: clientSource,
				storage: s,

				opts: Options{
					AuthValidityTime: 1 * time.Minute,
					CodeValidityTime: 1 * time.Minute,
				},

				now: time.Now,
			}

			var gotAuthReq *AuthorizationRequest
			h := &authFnHandlers{
				authorizer: &authorizer{o: oidc},
				startAuthorization: func(w http.ResponseWriter, req *http.Request, ar *AuthorizationRequest) {
					gotAuthReq = ar
					_, _ = fmt.Fprintf(w, "login page would go here")
				},
			}
			oidc.handler = h

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/?"+tc.Query.Encode(), nil)

			oidc.StartAuthorization(rec, req)

			if tc.WantHTTPStatus != 0 {
				if tc.WantHTTPStatus != rec.Code {
					t.Errorf("want HTTP status code %d, got: %d", tc.WantHTTPStatus, rec.Code)
				}
			}

			if tc.CheckHTTPReponse != nil {
				tc.CheckHTTPReponse(t, rec)
			}

			if tc.CheckResponse != nil {
				tc.CheckResponse(t, s, gotAuthReq)
			}
		})
	}
}

func TestFinishAuthorization(t *testing.T) {
	authReq := &storage.AuthRequest{
		ID:           uuid.Must(uuid.NewRandom()),
		RedirectURI:  "https://redir",
		State:        "state",
		Scopes:       []string{oidc.ScopeOpenID},
		Nonce:        "nonce",
		ResponseType: storage.AuthRequestResponseTypeCode,
		Expiry:       time.Now().Add(1 * time.Minute),
	}

	for _, tc := range []struct {
		Name                 string
		AuthReqID            uuid.UUID
		WantReturnedErrMatch func(error) bool
		WantHTTPStatus       int
		Check                func(t *testing.T, smgr storage.Storage, rec *httptest.ResponseRecorder)
	}{
		{
			Name:           "Redirects to the correct location",
			AuthReqID:      authReq.ID,
			WantHTTPStatus: 302,
			Check: func(t *testing.T, smgr storage.Storage, rec *httptest.ResponseRecorder) {
				loc := rec.Header().Get("location")

				// strip query to compare base URL
				lnqp, err := url.Parse(loc)
				if err != nil {
					t.Fatal(err)
				}
				lnqp.RawQuery = ""

				if lnqp.String() != authReq.RedirectURI {
					t.Errorf("want redir %s, got: %s", authReq.RedirectURI, lnqp.String())
				}

				locp, err := url.Parse(loc)
				if err != nil {
					t.Fatal(err)
				}

				// make sure the code resolves to an authCode
				codeid, _, err := unmarshalToken(locp.Query().Get("code"))
				if err != nil {
					t.Fatal(err)
				}
				gotCode, _, err := smgr.GetAuthCode(context.TODO(), codeid)
				if err != nil || gotCode == nil {
					t.Errorf("wanted no error fetching code, got: %v", err)
				}

				// make sure the state was passed
				state := locp.Query().Get("state")
				if authReq.State != state {
					t.Errorf("want state %s, got: %v", authReq.State, state)
				}
			},
		},
		{
			Name:                 "Invalid request ID fails",
			AuthReqID:            uuid.Must(uuid.NewRandom()),
			WantReturnedErrMatch: matchHTTPErrStatus(403),
			Check: func(t *testing.T, smgr storage.Storage, _ *httptest.ResponseRecorder) {
				// TODO what was this checking
				/*
					gotSess := &versionedSession{}
					ok, err := smgr.GetSession(context.Background(), sessID, gotSess)
					if err != nil {
						t.Errorf("unexpected error: %v", err)
					}
					if ok {
						t.Errorf("want: no session returned, got: %v", gotSess)
					}*/
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
			if err != nil {
				t.Fatal(err)
			}

			if err := s.PutAuthRequest(ctx, authReq); err != nil {
				t.Fatal(err)
			}

			oidcs := &OIDC{
				storage: s,
				now:     time.Now,

				opts: Options{
					AuthValidityTime: 1 * time.Minute,
					CodeValidityTime: 1 * time.Minute,
				},
			}
			authorizer := &authorizer{o: oidcs}

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", nil)

			err = authorizer.Authorize(rec, req, tc.AuthReqID, &Authorization{Scopes: []string{oidc.ScopeOpenID}})
			checkErrMatcher(t, tc.WantReturnedErrMatch, err)

			if tc.WantHTTPStatus != 0 {
				if tc.WantHTTPStatus != rec.Code {
					t.Errorf("want HTTP status code %d, got: %d", tc.WantHTTPStatus, rec.Code)
				}
			}

			if tc.Check != nil {
				tc.Check(t, s, rec)
			}
		})
	}
}

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
	)

	newOIDC := func() *OIDC {
		s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
		if err != nil {
			t.Fatal(err)
		}

		return &OIDC{
			issuer: issuer,

			storage: s,
			keyset:  testKeysets(),

			handler: &authFnHandlers{
				token: func(req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{
						Identity: &Identity{},
					}, nil
				},
			},

			clients: &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURLs: []string{redirectURI},
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURLs: []string{otherClientRedirect},
					},
				},
			},

			now: time.Now,
		}
	}

	newCodeSess := func(t *testing.T, smgr storage.Storage) (usertok string) {
		t.Helper()

		id := uuid.Must(uuid.NewRandom())
		utok, stok, err := newToken(id)
		if err != nil {
			t.Fatal(err)
		}

		utokstr, err := marshalToken(utok)
		if err != nil {
			t.Fatal(err)
		}

		auth := &storage.Authorization{
			ID:       uuid.Must(uuid.NewRandom()),
			Subject:  "testsub",
			ClientID: clientID,
		}
		if err := smgr.PutAuthorization(context.TODO(), auth); err != nil {
			t.Fatal(err)
		}

		sess := &storage.AuthCode{
			ID:              id,
			AuthorizationID: auth.ID,
			Code:            stok,
			Expiry:          time.Now().Add(1 * time.Minute),
		}

		if err := smgr.PutAuthCode(context.Background(), sess); err != nil {
			t.Fatal(err)
		}

		return utokstr
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeSess(t, o.storage)

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
		codeToken := newCodeSess(t, o.storage)

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
		codeToken := newCodeSess(t, o.storage)

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
		codeToken := newCodeSess(t, o.storage)

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
		codeToken := newCodeSess(t, o.storage)

		treq := &oauth2.TokenRequest{
			GrantType:    oauth2.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		o.handler = &authFnHandlers{
			token: func(req *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{
					IDTokenExpiry:     time.Now().Add(5 * time.Minute),
					AccessTokenExpiry: time.Now().Add(5 * time.Minute),
					Identity:          &Identity{},
				}, nil
			},
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

	newOIDC := func() *OIDC {
		s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
		if err != nil {
			t.Fatal(err)
		}

		return &OIDC{
			issuer: issuer,

			storage: s,
			keyset:  testKeysets(),

			handler: &authFnHandlers{
				refreshToken: func(req *RefreshTokenRequest) (*TokenResponse, error) {
					return &TokenResponse{
						Identity: &Identity{},
					}, nil
				},
			},

			clients: &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURLs: []string{redirectURI},
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURLs: []string{otherClientRedirect},
					},
				},
			},

			opts: Options{
				AuthValidityTime: 1 * time.Minute,
				CodeValidityTime: 1 * time.Minute,
				MaxRefreshTime:   6 * time.Hour,
			},

			now: time.Now,
		}
	}

	newRefreshSess := func(t *testing.T, smgr storage.Storage) (usertok string) {
		t.Helper()

		id := uuid.Must(uuid.NewRandom())
		utok, stok, err := newToken(id)
		if err != nil {
			t.Fatal(err)
		}

		utokstr, err := marshalToken(utok)
		if err != nil {
			t.Fatal(err)
		}

		auth := &storage.Authorization{
			ID:       uuid.Must(uuid.NewRandom()),
			Subject:  "testsub",
			ClientID: clientID,
			Scopes:   []string{oidc.ScopeOfflineAccess},
		}
		if err := smgr.PutAuthorization(context.TODO(), auth); err != nil {
			t.Fatal(err)
		}

		sess := &storage.RefreshSession{
			ID:              id,
			AuthorizationID: auth.ID,
			RefreshToken:    stok,
			Expiry:          time.Now().Add(60 * time.Minute),
		}

		if err := smgr.PutRefreshSession(context.Background(), sess); err != nil {
			t.Fatal(err)
		}

		return utokstr
	}

	t.Run("Refresh token happy path", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshSess(t, o.storage)

		o.handler = &authFnHandlers{
			refreshToken: func(req *RefreshTokenRequest) (*TokenResponse, error) {
				return &TokenResponse{
					Identity:                   &Identity{},
					OverrideRefreshTokenExpiry: o.now().Add(10 * time.Minute),
				}, nil
			},
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
		refreshToken := newRefreshSess(t, o.storage)

		var returnErr error
		const errDesc = "Refresh unauthorized"

		o.handler = &authFnHandlers{
			refreshToken: func(req *RefreshTokenRequest) (*TokenResponse, error) {
				if returnErr != nil {
					return nil, returnErr
				}
				return &TokenResponse{
					Identity:                   &Identity{},
					OverrideRefreshTokenExpiry: o.now().Add(10 * time.Minute),
				}, nil
			},
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
		refreshToken = newRefreshSess(t, o.storage)

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

	signAccessToken := func(cl oidc.AccessTokenClaims) string {
		h, err := testKeysets()[SigningAlgRS256](context.TODO())
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jwt.NewSigner(h)
		if err != nil {
			t.Fatal(err)
		}

		rawATJWT, err := cl.ToJWT(nil)
		if err != nil {
			t.Fatal(err)
		}

		sat, err := signer.SignAndEncode(rawATJWT)
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
				return signAccessToken(oidc.AccessTokenClaims{
					Issuer:  issuer,
					Subject: "sub",
					Expiry:  oidc.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
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
				return signAccessToken(oidc.AccessTokenClaims{
					Issuer:  "http://other",
					Subject: "sub",
					Expiry:  oidc.UnixTime(time.Now().Add(1 * time.Minute).Unix()),
				})
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "Expired access token",
			Setup: func(t *testing.T) (accessToken string) {
				return signAccessToken(oidc.AccessTokenClaims{
					Issuer:  issuer,
					Subject: "sub",
					Expiry:  oidc.UnixTime(time.Now().Add(-1 * time.Minute).Unix()),
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
			s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
			if err != nil {
				t.Fatal(err)
			}

			handlers := &authFnHandlers{
				userinfo: func(w io.Writer, uireq *UserinfoRequest) (*UserinfoResponse, error) {
					return nil, nil
				},
			}

			oidc, err := New(issuer, s, &staticclients.Clients{}, testKeysets(), handlers, nil)
			if err != nil {
				t.Fatal(err)
			}

			at := tc.Setup(t)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/userinfo", nil)

			if at != "" {
				req.Header.Set("authorization", "Bearer "+at)
			}

			oidc.Userinfo(rec, req)
			if tc.WantErr && rec.Result().StatusCode == http.StatusOK {
				t.Error("want error, but got none")
			}
			if !tc.WantErr && rec.Result().StatusCode != http.StatusOK {
				t.Errorf("want no error, got status: %d", rec.Result().StatusCode)
			}
		})
	}
}

func mustMarshal(u *corev1.UserToken) string {
	t, err := marshalToken(u)
	if err != nil {
		panic(err)
	}
	return t
}

func checkErrMatcher(t *testing.T, matcher func(error) bool, err error) {
	t.Helper()
	if err == nil && matcher != nil {
		t.Fatal("want error, got none")
	}
	if err != nil {
		if matcher == nil || !matcher(err) {
			t.Fatalf("unexpected error: %v", err)
		}
		// we have an error and it matched
	}
}

func matchAuthErrCode(code oauth2.AuthErrorCode) func(error) bool {
	return func(err error) bool {
		aerr, ok := err.(*oauth2.AuthError)
		if !ok {
			return false
		}
		return aerr.Code == code
	}
}

func matchTokenErrCode(code oauth2.TokenErrorCode) func(error) bool {
	return func(err error) bool {
		terr, ok := err.(*oauth2.TokenError)
		if !ok {
			return false
		}
		return terr.ErrorCode == code
	}
}

func matchHTTPErrStatus(code int) func(error) bool {
	return func(err error) bool {
		herr, ok := err.(*oauth2.HTTPError)
		if !ok {
			return false
		}
		return herr.Code == code
	}
}

func matchAnyErr() func(error) bool { // nolint:unused,varcheck,deadcode
	return func(err error) bool {
		return err != nil
	}
}

var (
	th   *keyset.Handle
	thMu sync.Mutex
)

func testKeysets() map[SigningAlg]HandleFn {
	thMu.Lock()
	defer thMu.Unlock()
	// we only make one, because it's slow
	if th == nil {
		h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
		if err != nil {
			panic(err)
		}
		th = h
	}

	return map[SigningAlg]HandleFn{
		SigningAlgRS256: StaticHandleFn(th),
	}
}
