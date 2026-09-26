package clitoken

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oauth2client"
)

func TestTokenSourceRequiresExplicitClientPolicy(t *testing.T) {
	client := &oauth2.Config{}
	for _, tc := range []struct {
		name   string
		config Config
		want   string
	}{
		{name: "missing client", config: Config{ClientType: oauth2client.PublicClient}, want: "OAuth2Client"},
		{name: "unknown type", config: Config{OAuth2Client: client, ClientType: oauth2client.ClientType(99)}, want: "client type"},
		{name: "public without PKCE", config: Config{OAuth2Client: client, ClientType: oauth2client.PublicClient, SkipPKCE: true}, want: "confidential"},
		{name: "unspecified without PKCE", config: Config{OAuth2Client: client, SkipPKCE: true}, want: "client type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.config.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("TokenSource() error = %v, want substring %q", err, tc.want)
			}
		})
	}
	confidential := Config{OAuth2Client: client, ClientType: oauth2client.ConfidentialClient, SkipPKCE: true}
	if _, err := confidential.TokenSource(context.Background()); err != nil {
		t.Fatalf("confidential client with PKCE disabled rejected: %v", err)
	}
}

type captureOpener struct {
	t    *testing.T
	urlC chan string
}

func (c *captureOpener) Open(ctx context.Context, url string) error {
	c.t.Logf("open called for: %s", url)
	c.urlC <- url
	return nil
}

func TestLocalTokenSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	t.Cleanup(cancel)

	const accessToken = "youareok"
	var postedRedirectURI string

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		redir := r.URL.Query().Get("redirect_uri")
		redir = redir + "?code=1234&state=" + r.URL.Query().Get("state")
		t.Logf("/auth redirect to: %s", redir)
		http.Redirect(w, r, redir, http.StatusSeeOther)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		postedRedirectURI = r.Form.Get("redirect_uri")
		w.Header().Add("Content-Type", "application/json;charset=UTF-8")
		resp := map[string]any{
			"access_token": accessToken,
			"expires_in":   60,
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)

	// needs this to trust the self-signed cert. Also a demo of how to use a
	// custom HTTP client.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, srv.Client())

	openC := make(chan string)
	co := &captureOpener{t: t, urlC: openC}

	cfg := Config{
		OAuth2Client: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				AuthURL:  srv.URL + "/auth",
				TokenURL: srv.URL + "/token",
			},
		},
		ClientType:      oauth2client.ConfidentialClient,
		SkipPKCE:        true,
		AuthCodeOptions: []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("resource", "https://api.example")},
		Opener:          co,
	}

	ts, err := cfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var (
		tokC            = make(chan *oauth2.Token)
		tokErrC         = make(chan error)
		authRedirectURI string
	)
	go func() {
		t, err := ts.Token()
		if err != nil {
			tokErrC <- err
			return
		}
		tokC <- t
	}()

	select {
	case acurl := <-openC:
		req, err := http.NewRequest(http.MethodGet, acurl, nil)
		if err != nil {
			t.Fatal(err)
		}
		authURL, err := url.Parse(acurl)
		if err != nil {
			t.Fatal(err)
		}
		if authURL.Query().Get("resource") != "https://api.example" {
			t.Fatalf("custom auth code option was lost when PKCE was disabled: %s", acurl)
		}
		if authURL.Query().Has("code_challenge") {
			t.Fatalf("confidential flow unexpectedly used PKCE: %s", acurl)
		}
		authRedirectURI = authURL.Query().Get("redirect_uri")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("resp status: %d", resp.StatusCode)
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for open")
	}

	select {
	case err := <-tokErrC:
		t.Fatal(err)
	case tok := <-tokC:
		if tok.AccessToken != accessToken {
			t.Errorf("want access token %s, got: %#v", accessToken, tok)
		}
		if postedRedirectURI == "" || postedRedirectURI != authRedirectURI {
			t.Errorf("authorization redirect_uri %q differs from exchange redirect_uri %q", authRedirectURI, postedRedirectURI)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for token")
	}
}
