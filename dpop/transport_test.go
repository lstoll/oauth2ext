package dpop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport(t *testing.T) {
	privKey := generateTestKey(t)

	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// TODO - we might want to expose the thumbprint from the encoder or
	// something? Let's see how it plays out.

	expectedThumbprint, err := calculateJWKThumbprint(signer.jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	var capturedDPoP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &Transport{
			Signer: signer,
		},
	}

	resp, err := client.Get(server.URL + "/test/path")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if capturedDPoP == "" {
		t.Fatal("DPoP header was not added to request")
	}

	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifier := &Verifier{}
	verifiedJWT, err := verifier.VerifyAndDecode(capturedDPoP, validator)
	if err != nil {
		t.Fatalf("failed to verify DPoP proof: %v", err)
	}

	if verifiedJWT == nil {
		t.Error("verifiedJWT is nil")
	}

	t.Logf("Successfully verified DPoP proof with thumbprint: %s", expectedThumbprint)
}

func TestTransport_NilSigner(t *testing.T) {
	transport := &Transport{}
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error with nil signer, got nil")
	}
}
