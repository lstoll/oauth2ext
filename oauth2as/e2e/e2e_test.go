package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lstoll/oauth2as"
	"github.com/lstoll/oauth2as/staticclients"
	"github.com/lstoll/oauth2as/storage"
	"github.com/lstoll/oauth2ext/oidc"
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

			s, err := storage.NewJSONFile(filepath.Join(t.TempDir(), "db.json"))
			if err != nil {
				t.Fatal(err)
			}

			/*mux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				ar, err := oidcHandlers.StartAuthorization(w, req)
				if err != nil {
					t.Fatalf("error starting authorization flow: %v", err)
				}

				// just finish it straight away
				if err := oidcHandlers.FinishAuthorization(w, req, ar.SessionID, &op.Authorization{Scopes: []string{"openid"}}); err != nil {
					t.Fatalf("error finishing authorization: %v", err)
				}
			})

			mux.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
				err := oidcHandlers.Token(w, req, func(tr *op.TokenRequest) (*op.TokenResponse, error) {
					return &op.TokenResponse{
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
				err := oidcHandlers.Userinfo(w, req, func(w io.Writer, _ *op.UserinfoRequest) error {
					fmt.Fprintf(w, `{
						"sub": "test-sub"
					}`)
					return nil
				})
				if err != nil {
					t.Errorf("error in userinfo endpoint: %v", err)
				}
			})*/

			oidcSvr := httptest.NewServer(nil)
			t.Cleanup(oidcSvr.Close)

			opcfg := oauth2as.Config{
				Issuer:  oidcSvr.URL,
				Storage: s,
				Keyset:  testKeysets(),
				TokenHandler: func(req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
					return &oauth2as.TokenResponse{Identity: &oauth2as.Identity{}}, nil
				},
				UserinfoHandler: func(w io.Writer, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
					return &oauth2as.UserinfoResponse{Identity: &oauth2as.Identity{}}, nil
				},
				Clients: clientSource,
			}

			op, err := oauth2as.NewServer(opcfg)
			if err != nil {
				t.Fatal(err)
			}
			oidcSvr.Config.Handler = op

			// privh, err := testKeysets()[oauth2as.SigningAlgRS256](ctx)
			// if err != nil {
			// 	t.Fatal(err)
			// }
			// pubh, err := privh.Public()
			// if err != nil {
			// 	t.Fatal(err)
			// }

			// discovery endpoint
			// md := discovery.DefaultCoreMetadata(oidcSvr.URL)
			// md.Issuer = oidcSvr.URL
			// md.AuthorizationEndpoint = oidcSvr.URL + "/authorization"
			// md.TokenEndpoint = oidcSvr.URL + "/token"
			// md.UserinfoEndpoint = oidcSvr.URL + "/userinfo"

			// discoh, err := discovery.NewConfigurationHandler(md, oidc.NewStaticPublicHandle(pubh))
			// if err != nil {
			// 	t.Fatalf("Failed to initialize discovery handler: %v", err)
			// }
			// mux.Handle("GET /.well-known/openid-configuration", discoh)
			// mux.Handle("GET /.well-known/jwks.json", discoh)

			provider, err := oidc.DiscoverProvider(ctx, oidcSvr.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			o2 := &oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  cliSvr.URL,
				Scopes:       []string{oidc.ScopeOfflineAccess},
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
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("expected status found, got %d", resp.StatusCode)
			}

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

				// TODO - how to do this?
				// if err := smgr.expireAccessTokens(ctx); err != nil {
				// 	t.Fatalf("expiring tokens: %v", err)
				// }
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

var (
	th   *keyset.Handle
	thMu sync.Mutex
)

func testKeysets() oauth2as.AlgKeysets {
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

	return oauth2as.NewSingleAlgKeysets(oauth2as.SigningAlgRS256, th)
}
