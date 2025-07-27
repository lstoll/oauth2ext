package main

import (
	_ "embed"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lstoll/oauth2as"
	"github.com/lstoll/oauth2as/staticclients"
	"github.com/lstoll/oauth2as/storage"
)

//go:embed clients.json
var clientsJSON []byte

func main() {
	store, err := storage.NewJSONFile(filepath.Join(os.TempDir(), "oidc-example-op.json"))
	if err != nil {
		log.Fatalf("creating storage: %v", err)
	}
	privh, _ := mustInitKeyset()

	clients, err := staticclients.ExpandUnmarshal(clientsJSON)
	if err != nil {
		log.Fatalf("parsing clients: %v", err)
	}

	iss := "http://localhost:8085"

	svr := &server{}

	core, err := oauth2as.New(
		iss,
		store,
		clients,
		map[oauth2as.SigningAlg]oauth2as.HandleFn{
			oauth2as.SigningAlgRS256: oauth2as.StaticHandleFn(privh),
		},
		svr,
		&oauth2as.Options{
			Issuer:           iss,
			AuthValidityTime: 5 * time.Minute,
			CodeValidityTime: 5 * time.Minute,
		})
	if err != nil {
		log.Fatalf("Failed to create OIDC server instance: %v", err)
	}

	m := http.NewServeMux()
	if err := core.AttachHandlers(m, nil); err != nil {
		log.Fatalf("failed to attach oidc handlers: %v", err)
	}
	m.HandleFunc("/finish", svr.finishAuthorization)

	log.Printf("Listening on: %s", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", m)
	if err != nil {
		log.Fatal(err)
	}
}
