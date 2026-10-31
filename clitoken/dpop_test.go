package clitoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2client"
	"lds.li/oauth2ext/tokencache"
)

func TestLocalTokenSourceDPoP(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}

	var exchangeThumb string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=1234&state="+r.URL.Query().Get("state"), http.StatusSeeOther)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		validator, err := dpop.NewValidator(&dpop.ValidatorOpts{IgnoreThumbprint: true})
		if err != nil {
			t.Error(err)
		}
		proof, err := (&dpop.Verifier{}).VerifyAndDecode(r.Header.Get("DPoP"), validator)
		if err != nil {
			t.Errorf("exchange proof: %v", err)
		} else {
			exchangeThumb = proof.Thumbprint
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "bound", "token_type": "DPoP", "expires_in": 60})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	openC := make(chan string, 1)
	cfg := Config{
		OAuth2Client: &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token"}},
		ClientType:   oauth2client.PublicClient,
		Opener:       &captureOpener{t: t, urlC: openC},
	}
	ts, err := cfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dts, ok := ts.(tokencache.DPoPTokenSource)
	if !ok {
		t.Fatal("token source does not implement tokencache.DPoPTokenSource")
	}

	type result struct {
		tok *oauth2.Token
		err error
	}
	resC := make(chan result, 1)
	go func() {
		tok, err := dts.DPoPToken(signer)
		resC <- result{tok, err}
	}()

	select {
	case acurl := <-openC:
		u, err := url.Parse(acurl)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Query().Get("dpop_jkt"); got != signer.Thumbprint() {
			t.Errorf("dpop_jkt = %q, want %q", got, signer.Thumbprint())
		}
		resp, err := srv.Client().Get(acurl)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for open")
	}

	select {
	case res := <-resC:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.tok.AccessToken != "bound" {
			t.Errorf("unexpected token %+v", res.tok)
		}
		if exchangeThumb != signer.Thumbprint() {
			t.Errorf("exchange proof key %q, want %q", exchangeThumb, signer.Thumbprint())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for token")
	}
}
