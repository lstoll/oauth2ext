package main

import (
	_ "embed"
	"log/slog"
	"net/http"
	"time"

	"github.com/lstoll/oauth2as"
	"github.com/lstoll/oauth2as/staticclients"
)

//go:embed clients.json
var clientsJSON []byte

func main() {
	// Use in-memory storage instead of JSON file
	store := oauth2as.NewMemStorage()

	clients, err := staticclients.ExpandUnmarshal(clientsJSON)
	if err != nil {
		slog.Error("parsing clients", "error", err)
		return
	}

	iss := "http://localhost:8085"

	svr := &server{}

	// Create keyset for RS256
	privHandle, _ := mustInitKeyset()
	keyset := oauth2as.NewSingleAlgKeysets(oauth2as.SigningAlgRS256, privHandle)

	// Create server with new API
	core, err := oauth2as.NewServer(oauth2as.Config{
		Issuer:  iss,
		Storage: store,
		Clients: clients,
		Keyset:  keyset,
		Logger:  slog.Default(),

		// Token handler
		TokenHandler: svr.handleToken,

		// Userinfo handler
		UserinfoHandler: svr.handleUserinfo,

		// Configuration
		AuthValidityTime:    5 * time.Minute,
		CodeValidityTime:    5 * time.Minute,
		IDTokenValidity:     1 * time.Hour,
		AccessTokenValidity: 1 * time.Hour,
		MaxRefreshTime:      30 * 24 * time.Hour,

		// Paths
		AuthorizationPath: "/authorize",
		TokenPath:         "/token",
		UserinfoPath:      "/userinfo",
	})
	if err != nil {
		slog.Error("Failed to create OIDC server instance", "error", err)
		return
	}

	// Set the core reference in the server
	svr.SetCore(core)

	m := http.NewServeMux()

	// Add authorization endpoint handler
	m.HandleFunc("/authorize", svr.StartAuthorization)

	// Attach the server's handlers for token and userinfo
	m.Handle("/", core)

	// Add our custom finish endpoint
	m.HandleFunc("/finish", svr.finishAuthorization)

	slog.Info("Listening on", "address", "localhost:8085")
	err = http.ListenAndServe("localhost:8085", m)
	if err != nil {
		slog.Error("Server failed", "error", err)
	}
}
