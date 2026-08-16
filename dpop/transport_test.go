package dpop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport(t *testing.T) {
	privKey := generateTestKey(t)
	signer := mustSigner(t, privKey)
	expectedThumbprint := signer.KeyID()

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

	req, err := http.NewRequest(http.MethodGet, server.URL+"/test/path?ignored=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "DPoP access-token")
	resp, err := client.Do(req)
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
		ExpectedHTM:        new(http.MethodGet),
		ExpectedHTU:        new(server.URL + "/test/path"),
	})
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	verifier := &Verifier{}
	proof, err := verifier.VerifyAndDecode(capturedDPoP, validator)
	if err != nil {
		t.Fatalf("failed to verify DPoP proof: %v", err)
	}

	if proof.AccessTokenHash != hashAccessToken("access-token") {
		t.Errorf("ath: got %q, want %q", proof.AccessTokenHash, hashAccessToken("access-token"))
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
