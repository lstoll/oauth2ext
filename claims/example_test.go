package claims

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/internal/th"
	"lds.li/oauth2ext/provider"
)

func ExampleVerifier_VerifyAndDecode() {
	ctx := context.Background()

	server, signer := newMockDiscoveryServer()
	defer server.Close()

	provider, err := provider.DiscoverOIDCProvider(context.WithValue(ctx, oauth2.HTTPClient, server.Client()), server.URL)
	if err != nil {
		log.Fatalf("failed to discover provider: %v", err)
	}

	verifier, err := NewVerifier[*VerifiedID](provider)
	if err != nil {
		log.Fatalf("failed to create verifier: %v", err)
	}

	validator := NewIDTokenValidator(&IDTokenValidatorOpts{
		ClientID: th.Ptr("client-id"),
	})

	rawJWT, err := jwt.NewRawJWT(&jwt.RawJWTOptions{
		Issuer:    th.Ptr(server.URL),
		Audience:  th.Ptr("client-id"),
		Subject:   th.Ptr("subject"),
		IssuedAt:  th.Ptr(time.Now()),
		ExpiresAt: th.Ptr(time.Now().Add(time.Hour)),
	})
	if err != nil {
		log.Fatalf("failed to create raw JWT: %v", err)
	}

	compact, err := signer.Sign(rawJWT)
	if err != nil {
		log.Fatalf("failed to sign raw JWT: %v", err)
	}

	verified, err := verifier.VerifyAndDecode(ctx, compact, validator)
	if err != nil {
		log.Fatalf("failed to verify and decode JWT: %v", err)
	}

	sub, err := verified.Subject()
	if err != nil {
		log.Fatalf("failed to get subject: %v", err)
	}
	fmt.Println(sub)

	// Output: subject
}

// newMockDiscoveryServer creates a mock OIDC discovery server for testing.
// The caller is responsible for cleanup (e.g., using t.Cleanup or defer).
func newMockDiscoveryServer() (*httptest.Server, *internal.TestSigner) {
	testSigner := internal.NewTestSigner()

	svr := httptest.NewTLSServer(nil)

	mux := http.NewServeMux()

	pmd := &provider.OIDCProviderMetadata{
		Issuer:                           svr.URL,
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
		JWKSURI:                          svr.URL + "/.well-known/jwks.json",
	}

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(pmd); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")

		if _, err := w.Write(testSigner.JWKS()); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
	})

	svr.Config.Handler = mux

	return svr, testSigner
}
