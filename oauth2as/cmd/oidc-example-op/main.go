package main

import (
	_ "embed"
	"log"
	"net/http"
	"time"

	"github.com/lstoll/oidc"
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

	iss := "http://localhost:8085"

	core, err := core.New(&core.Config{
		Issuer:           iss,
		AuthValidityTime: 5 * time.Minute,
		CodeValidityTime: 5 * time.Minute,
	}, smgr, clients, core.NewStaticKeysetHandle(privh))
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	m := http.NewServeMux()

	svr := &server{
		oidc:            core,
		storage:         smgr,
		tokenValidFor:   30 * time.Second,
		refreshValidFor: 5 * time.Minute,
	}

	m.Handle("/", svr)

	md := discovery.DefaultCoreMetadata(iss)
	md.AuthorizationEndpoint = iss + "/auth"
	md.TokenEndpoint = iss + "/token"

	discoh, err := discovery.NewConfigurationHandler(md, oidc.NewStaticPublicHandle(pubh))
	if err != nil {
		log.Fatalf("Failed to initialize discovery handler: %v", err)
	}
	m.Handle("GET /.well-known/openid-configuration", discoh)
	m.Handle("GET /.well-known/jwks.json", discoh)

	log.Printf("Listening on: %s", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", m)
	if err != nil {
		log.Fatal(err)
	}
}
