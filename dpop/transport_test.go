package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport(t *testing.T) {
	// Generate a test key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encoder, err := NewDPopEncoder(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	// TODO - we might want to expose the thumbprint from the encoder or
	// something? Let's see how it plays out.

	expectedThumbprint, err := calculateJWKThumbprint(encoder.jwk)
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
			Encoder: encoder,
		},
	}

	resp, err := client.Get(server.URL + "/test/path")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if capturedDPoP == "" {
		t.Fatal("DPoP header was not added to request")
	}

	validator, err := NewValidator(&ValidatorOpts{
		ExpectedThumbprint: expectedThumbprint,
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifier := &DPoPVerifier{}
	verifiedJWT, err := verifier.VerifyAndDecode(capturedDPoP, validator)
	if err != nil {
		t.Fatalf("failed to verify DPoP proof: %v", err)
	}

	if verifiedJWT == nil {
		t.Error("verifiedJWT is nil")
	}

	t.Logf("Successfully verified DPoP proof with thumbprint: %s", expectedThumbprint)
}

func TestTransport_NilEncoder(t *testing.T) {
	transport := &Transport{}
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error with nil encoder, got nil")
	}
}
