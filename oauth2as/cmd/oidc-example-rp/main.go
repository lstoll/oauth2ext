package main

import (
	"context"
	"flag"
	"log"
	"net/http"

	"github.com/lstoll/oidc"
	"golang.org/x/oauth2"
)

const (
	clientID     = "client-id"
	clientSecret = "client-secret"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := struct {
		Issuer       string
		ClientID     string
		ClientSecret string
		RedirectURL  string
	}{
		Issuer:       "http://localhost:8085",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8084/callback",
	}

	flag.StringVar(&cfg.Issuer, "issuer", cfg.Issuer, "issuer")
	flag.StringVar(&cfg.ClientID, "client-id", cfg.ClientID, "client ID")
	flag.StringVar(&cfg.ClientSecret, "client-secret", cfg.ClientSecret, "client secret")
	flag.StringVar(&cfg.RedirectURL, "redirect-url", cfg.RedirectURL, "redirect URL")

	flag.Parse()

	provider, err := oidc.DiscoverProvider(ctx, cfg.Issuer, nil)
	if err != nil {
		log.Fatalf("discovering issuer: %v", err)
	}

	scopes := []string{oidc.ScopeOpenID}

	oa2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  cfg.RedirectURL,
	}

	svr := &server{
		provider:       provider,
		oa2Cfg:         oa2Cfg,
		pkceChallenges: make(map[string]string),
	}

	log.Printf("Listening on: %s", "http://localhost:8084")
	err = http.ListenAndServe("localhost:8084", svr)
	if err != nil {
		log.Fatal(err)
	}
}
