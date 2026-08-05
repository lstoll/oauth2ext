package claims

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/jwttest"
	"lds.li/oauth2ext/provider"
)

func TestIDTokenVerifier(t *testing.T) {
	server, signer := newMockDiscoveryServer(t)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	provider, err := provider.DiscoverOIDCProvider(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "client-id"
	verifier, err := NewIDTokenVerifier(provider, IDTokenVerifierOpts{ClientID: &clientID})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("token response", func(t *testing.T) {
		nonce := "request-nonce"
		accessToken := "access-token"
		claims := validIDClaims(server.URL, clientID)
		claims["nonce"] = nonce
		claims["at_hash"] = mustTokenHash(t, jwt.ES256, accessToken)
		compact := signClaims(t, signer, claims)
		token := (&oauth2.Token{AccessToken: accessToken}).WithExtra(map[string]any{"id_token": compact})

		verified, err := verifier.VerifyTokenResponse(ctx, token, IDTokenValidationInput{
			ExpectedNonce: &nonce,
		})
		if err != nil {
			t.Fatal(err)
		}
		if subject, err := verified.Subject(); err != nil || subject != "subject" {
			t.Fatalf("subject = %q, %v", subject, err)
		}
	})

	t.Run("wrong nonce", func(t *testing.T) {
		claims := validIDClaims(server.URL, clientID)
		claims["nonce"] = "wrong"
		compact := signClaims(t, signer, claims)
		want := "request-nonce"
		_, err := verifier.Verify(ctx, compact, IDTokenValidationInput{
			Source:        IDTokenFromTokenEndpoint,
			ExpectedNonce: &want,
		})
		requireIDVerificationError(t, err, "nonce")
	})

	t.Run("subject required", func(t *testing.T) {
		claims := validIDClaims(server.URL, clientID)
		delete(claims, "sub")
		_, err := verifier.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
			Source:      IDTokenFromTokenEndpoint,
			IgnoreNonce: true,
		})
		requireIDVerificationError(t, err, "subject")
	})

	for name, subject := range map[string]string{
		"empty subject":     "",
		"non-ASCII subject": "café",
		"long subject":      strings.Repeat("a", 256),
	} {
		t.Run(name, func(t *testing.T) {
			claims := validIDClaims(server.URL, clientID)
			claims["sub"] = subject
			_, err := verifier.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
				Source:      IDTokenFromTokenEndpoint,
				IgnoreNonce: true,
			})
			requireIDVerificationError(t, err, "subject")
		})
	}

	t.Run("multiple audiences require matching azp", func(t *testing.T) {
		claims := validIDClaims(server.URL, clientID)
		claims["aud"] = []string{clientID, "api"}
		input := IDTokenValidationInput{Source: IDTokenFromTokenEndpoint, IgnoreNonce: true}
		_, err := verifier.Verify(ctx, signClaims(t, signer, claims), input)
		requireIDVerificationError(t, err, "azp")
		claims["azp"] = clientID
		if _, err := verifier.Verify(ctx, signClaims(t, signer, claims), input); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIDTokenFlowValidation(t *testing.T) {
	server, signer := newMockDiscoveryServer(t)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	provider, err := provider.DiscoverOIDCProvider(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "client-id"
	verifier, err := NewIDTokenVerifier(provider, IDTokenVerifierOpts{ClientID: &clientID})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("authorization endpoint hashes", func(t *testing.T) {
		accessToken := "access-token"
		code := "authorization-code"
		claims := validIDClaims(server.URL, clientID)
		claims["at_hash"] = mustTokenHash(t, jwt.ES256, accessToken)
		claims["c_hash"] = mustTokenHash(t, jwt.ES256, code)
		_, err := verifier.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
			Source:            IDTokenFromAuthorizationEndpoint,
			IgnoreNonce:       true,
			AccessToken:       &accessToken,
			AuthorizationCode: &code,
		})
		if err != nil {
			t.Fatal(err)
		}
		delete(claims, "c_hash")
		_, err = verifier.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
			Source:            IDTokenFromAuthorizationEndpoint,
			IgnoreNonce:       true,
			AccessToken:       &accessToken,
			AuthorizationCode: &code,
		})
		requireIDVerificationError(t, err, "c_hash is required")
	})

	t.Run("max age", func(t *testing.T) {
		claims := validIDClaims(server.URL, clientID)
		claims["auth_time"] = time.Now().Add(-10 * time.Minute).Unix()
		maxAge := time.Minute
		_, err := verifier.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
			Source:      IDTokenFromTokenEndpoint,
			IgnoreNonce: true,
			MaxAge:      &maxAge,
		})
		requireIDVerificationError(t, err, "authentication age")
	})
}

func TestMappedIDTokenVerifier(t *testing.T) {
	server, signer := newMockDiscoveryServer(t)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	provider, err := provider.DiscoverOIDCProvider(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientID := "client-id"
	base, err := NewIDTokenVerifier(provider, IDTokenVerifierOpts{ClientID: &clientID})
	if err != nil {
		t.Fatal(err)
	}

	type appID struct {
		id           *VerifiedID
		groups       []string
		employeeType string
	}
	parse := func(id *VerifiedID) (*appID, error) {
		groups, err := id.ArrayOf[string]("groups")
		if err != nil {
			return nil, err
		}
		employeeType, err := id.String("employee_type")
		if err != nil {
			return nil, err
		}
		return &appID{id: id, groups: groups, employeeType: employeeType}, nil
	}
	requireGroup := func(group string) IDClaimsRule[*appID] {
		return func(id *appID) error {
			if !slices.Contains(id.groups, group) {
				return fmt.Errorf("required group is missing")
			}
			return nil
		}
	}
	requireEmployeeType := func(employeeType string) IDClaimsRule[*appID] {
		return func(id *appID) error {
			if id.employeeType != employeeType {
				return fmt.Errorf("employee type is not permitted")
			}
			return nil
		}
	}
	mapped := MapIDTokenClaims(base, WithIDClaimsRules(
		parse,
		requireGroup("engineering"),
		requireEmployeeType("employee"),
	))

	claims := validIDClaims(server.URL, clientID)
	claims["groups"] = []string{"engineering", "on-call"}
	claims["employee_type"] = "employee"
	compact := signClaims(t, signer, claims)
	got, err := mapped.Verify(ctx, compact, IDTokenValidationInput{
		Source:      IDTokenFromTokenEndpoint,
		IgnoreNonce: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.id == nil || got.employeeType != "employee" {
		t.Fatalf("mapped claims = %#v", got)
	}

	claims["employee_type"] = "contractor"
	_, err = mapped.Verify(ctx, signClaims(t, signer, claims), IDTokenValidationInput{
		Source:      IDTokenFromTokenEndpoint,
		IgnoreNonce: true,
	})
	if err == nil || !strings.Contains(err.Error(), "employee type") {
		t.Fatalf("error = %v, want employee type error", err)
	}
}

func TestNewIDTokenVerifierValidatesOptions(t *testing.T) {
	var nilProvider Provider
	if _, err := NewIDTokenVerifier(nilProvider, IDTokenVerifierOpts{IgnoreClientID: true}); err == nil {
		t.Fatal("expected nil provider error")
	}
}

func validIDClaims(issuer, audience string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": issuer,
		"sub": "subject",
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

func signClaims(t *testing.T, signer *jwttest.Signer, claims map[string]any) string {
	t.Helper()
	compact, err := signer.SignClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mustTokenHash(t *testing.T, algorithm jwt.Algorithm, value string) string {
	t.Helper()
	hash, err := oidcTokenHash(algorithm, value)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func requireIDVerificationError(t *testing.T, err error, detail string) *VerificationError {
	t.Helper()
	verificationErr, ok := errors.AsType[*VerificationError](err)
	if !ok {
		t.Fatalf("error: got %T %v, want *VerificationError", err, err)
	}
	if got := err.Error(); got != "claims: ID token verification failed" {
		t.Fatalf("public error: got %q", got)
	}
	if !strings.Contains(verificationErr.Details(), detail) {
		t.Fatalf("details: got %q, want text %q", verificationErr.Details(), detail)
	}
	return verificationErr
}

func newMockDiscoveryServer(t *testing.T) (*httptest.Server, *jwttest.Signer) {
	t.Helper()
	signer := jwttest.NewSigner(t)
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&provider.OIDCProviderMetadata{
			Issuer:                           server.URL,
			IDTokenSigningAlgValuesSupported: []string{"ES256"},
			JWKSURI:                          server.URL + "/jwks",
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signer.JWKS())
	})
	server.Config.Handler = mux
	return server, signer
}
