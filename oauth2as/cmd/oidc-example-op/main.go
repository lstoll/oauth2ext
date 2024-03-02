package main

import (
	_ "embed"
	"log"
	"net/http"
	"time"

	"github.com/lstoll/oidc/core"
	"github.com/lstoll/oidc/core/staticclients"
	"github.com/lstoll/oidc/discovery"
)

//go:embed clients.json
var clientsJSON []byte

func main() {
	smgr := newStubSMGR()
	privh, pubh := mustInitKeyset()

	clients, err := staticclients.ExpandUnmarshal(clientsJSON)
	if err != nil {
		log.Fatalf("parsing clients: %v", err)
	}

	oidc, err := core.New(&core.Config{
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, smgr, clients, core.StaticKeysetHandle(privh))
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	iss := "http://localhost:8085"

	m := http.NewServeMux()

	svr := &server{
		oidc:            oidc,
		storage:         smgr,
		tokenValidFor:   30 * time.Second,
		refreshValidFor: 5 * time.Minute,
	}

	m.Handle("/", svr)

	md := &discovery.ProviderMetadata{
		Issuer:                        iss,
		AuthorizationEndpoint:         iss + "/auth",
		TokenEndpoint:                 iss + "/token",
		JWKSURI:                       iss + "/jwks.json",
		CodeChallengeMethodsSupported: []discovery.CodeChallengeMethod{discovery.CodeChallengeMethodS256},
	}

	discoh, err := discovery.NewConfigurationHandler(md, discovery.WithCoreDefaults())
	if err != nil {
		log.Fatalf("Failed to initialize discovery handler: %v", err)
	}
	m.Handle("/.well-known/openid-configuration/", discoh)

	jwksh, err := discovery.NewKeysHandler(discovery.StaticPublicKeysetHandle(pubh), 1*time.Second)
	if err != nil {
		log.Fatalf("creating keys handler: %v", err)
	}
	m.Handle("/jwks.json", jwksh)

	log.Printf("Listening on: %s", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", m)
	if err != nil {
		log.Fatal(err)
	}
}
