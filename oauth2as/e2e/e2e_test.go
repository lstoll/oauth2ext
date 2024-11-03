package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidcop"
	"github.com/lstoll/oidcop/discovery"
	"github.com/lstoll/oidcop/staticclients"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

func TestE2E(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	for _, tc := range []struct {
		Name     string
		WithPKCE bool
	}{
		{
			Name: "Simple authorization",
		},
		{
			Name:     "Authorization with PKCE",
			WithPKCE: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			callbackChan := make(chan string, 1)
			state := randomStateValue()

			cliSvr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if errMsg := req.FormValue("error"); errMsg != "" {
					t.Errorf("error returned to callback %s: %s", errMsg, req.FormValue("error_description"))

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				code := req.FormValue("code")
				if code == "" {
					t.Error("no code in callback response")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				gotState := req.FormValue("state")
				if gotState == "" || gotState != state {
					t.Errorf("returned state doesn't match request state")

					w.WriteHeader(http.StatusBadRequest)
					return
				}

				callbackChan <- code
			}))
			defer cliSvr.Close()

			cfg := &oidcop.Config{
				Issuer:           "http://issuer",
				AuthValidityTime: 1 * time.Minute,
				CodeValidityTime: 1 * time.Minute,
			}
			smgr := newStubSMGR()
			clientSource := &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURLs: []string{cliSvr.URL},
						Public:       tc.WithPKCE,
					},
				},
			}

			oidcHandlers, err := oidcop.New(cfg, smgr, clientSource, testKeysetHandle())
			if err != nil {
				t.Fatal(err)
			}

			mux := http.NewServeMux()
			oidcSvr := httptest.NewServer(mux)
			defer oidcSvr.Close()

			mux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				ar, err := oidcHandlers.StartAuthorization(w, req)
				if err != nil {
					t.Fatalf("error starting authorization flow: %v", err)
				}

				// just finish it straight away
				if err := oidcHandlers.FinishAuthorization(w, req, ar.SessionID, &oidcop.Authorization{Scopes: []string{"openid"}}); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Token(w, req, func(tr *oidcop.TokenRequest) (*oidcop.TokenResponse, error) {
					return &oidcop.TokenResponse{
						IDToken:                tr.PrefillIDToken("test-sub", time.Now().Add(1*time.Minute)),
						AccessToken:            tr.PrefillAccessToken("test-sub", time.Now().Add(1*time.Minute)),
						IssueRefreshToken:      true,
						RefreshTokenValidUntil: time.Now().Add(2 * time.Minute),
					}, nil
				})
				if err != nil {
					t.Errorf("error in token endpoint: %v", err)
				}
			})

			mux.HandleFunc("/userinfo", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Userinfo(w, req, func(w io.Writer, _ *oidcop.UserinfoRequest) error {
					fmt.Fprintf(w, `{
						"sub": "test-sub"
					}`)
					return nil
				})
				if err != nil {
					t.Errorf("error in userinfo endpoint: %v", err)
				}
			})

			privh, err := testKeysetHandle().Handle(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pubh, err := privh.Public()
			if err != nil {
				t.Fatal(err)
			}

			// discovery endpoint
			md := discovery.DefaultCoreMetadata(oidcSvr.URL)
			md.Issuer = oidcSvr.URL
			md.AuthorizationEndpoint = oidcSvr.URL + "/authorization"
			md.TokenEndpoint = oidcSvr.URL + "/token"
			md.UserinfoEndpoint = oidcSvr.URL + "/userinfo"

			discoh, err := discovery.NewConfigurationHandler(md, oidc.NewStaticPublicHandle(pubh))
			if err != nil {
				t.Fatalf("Failed to initialize discovery handler: %v", err)
			}
			mux.Handle("GET /.well-known/openid-configuration", discoh)
			mux.Handle("GET /.well-known/jwks.json", discoh)

			provider, err := oidc.DiscoverProvider(ctx, oidcSvr.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			o2 := &oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  cliSvr.URL,
			}

			var acopts []oauth2.AuthCodeOption
			verifier := oauth2.GenerateVerifier()
			if tc.WithPKCE {
				acopts = append(acopts, oauth2.S256ChallengeOption(verifier))
			}

			client := &http.Client{}
			resp, err := client.Get(o2.AuthCodeURL(state, acopts...))
			if err != nil {
				t.Fatalf("error getting auth URL: %v", err)
			}
			defer resp.Body.Close()

			var callbackCode string
			select {
			case callbackCode = <-callbackChan:
			case <-time.After(1 * time.Second):
				t.Fatal("waiting for callback timed out after 1s")
			}

			var eopts []oauth2.AuthCodeOption
			if tc.WithPKCE {
				eopts = append(eopts, oauth2.VerifierOption(verifier))
			}

			tok, err := o2.Exchange(ctx, callbackCode, eopts...)
			if err != nil {
				t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
			}

			ts := o2.TokenSource(ctx, tok)

			_, uir, err := provider.Userinfo(ctx, ts)
			if err != nil {
				t.Fatalf("error fetching userinfo: %v", err)
			}

			t.Logf("initial userinfo response: %#v", uir)

			for i := 0; i < 5; i++ {
				t.Logf("refresh iter: %d", i)
				currRT := tok.RefreshToken

				if err := smgr.expireAccessTokens(ctx); err != nil {
					t.Fatalf("expiring tokens: %v", err)
				}
				tok.Expiry = time.Now().Add(-1 * time.Second) // needs to line up with remote change, else we won't refresh

				_, uir, err := provider.Userinfo(ctx, ts)
				if err != nil {
					t.Fatalf("error fetching userinfo: %v", err)
				}

				t.Logf("subsequent userinfo response: %#v", uir)

				nt, err := ts.Token()
				if err != nil {
					t.Fatal(err)
				}

				if currRT == nt.RefreshToken {
					t.Fatal("userinfo should result in new refresh token")
				}

				tok = nt
			}
		})
	}
}

func randomStateValue() string {
	const numBytes = 16

	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}

// contains helpers used by multiple tests

type stubSMGR struct {
	// sessions maps JSON session objects by their ID
	// JSON > proto here for better debug output
	sessions map[string]string
}

func newStubSMGR() *stubSMGR {
	return &stubSMGR{
		sessions: map[string]string{},
	}
}

func (s *stubSMGR) NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *stubSMGR) GetSession(_ context.Context, sessionID string, into oidcop.Session) (found bool, err error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal([]byte(sess), into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess oidcop.Session) error {
	if sess.ID() == "" {
		return fmt.Errorf("session has no ID")
	}
	strsess, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.ID()] = string(strsess)
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

// expireAccessTokens will set all the access token expirations to a time before
// now.
func (s *stubSMGR) expireAccessTokens(_ context.Context) error {
	for id, sd := range s.sessions {
		sm := map[string]interface{}{}
		if err := json.Unmarshal([]byte(sd), &sm); err != nil {
			return err
		}
		ati, ok := sm["access_token"]
		if !ok {
			continue // no access token in this session, skip
		}
		at := ati.(map[string]interface{})
		at["expires_at"] = time.Now().Add(-1 * time.Second).Format(time.RFC3339)
		sd, err := json.Marshal(sm)
		if err != nil {
			return err
		}
		s.sessions[id] = string(sd)
	}
	return nil
}

var (
	th     *keyset.Handle
	thOnce sync.Once
)

func testKeysetHandle() oidcop.KeysetHandle {
	thOnce.Do(func() {
		// we only make one, because it's slow
		if th == nil {
			h, err := keyset.NewHandle(jwt.ES256Template())
			if err != nil {
				panic(err)
			}
			th = h
		}
	})

	return oidcop.NewStaticKeysetHandle(th)
}
