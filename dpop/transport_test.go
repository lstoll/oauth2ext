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

	// Create a test server that captures the DPoP header
	var capturedDPoP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a client with DPoP transport
	client := &http.Client{
		Transport: &Transport{
			Encoder: encoder,
		},
	}

	// Make a request
	resp, err := client.Get(server.URL + "/test/path")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Check that DPoP header was added
	if capturedDPoP == "" {
		t.Fatal("DPoP header was not added to request")
	}

	// Verify the DPoP proof
	verifier := &DPoPVerifier{}
	result, err := verifier.VerifyAndDecode(capturedDPoP)
	if err != nil {
		t.Fatalf("failed to verify DPoP proof: %v", err)
	}

	// Verify we got a valid result with thumbprint
	if result.Thumbprint == "" {
		t.Error("thumbprint is empty")
	}

	t.Logf("Successfully verified DPoP proof with thumbprint: %s", result.Thumbprint)
}

func TestTransport_NilEncoder(t *testing.T) {
	transport := &Transport{}
	req := httptest.NewRequest("GET", "http://example.com", nil)

	_, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error with nil encoder, got nil")
	}
}

func TestTransport_WithCustomBase(t *testing.T) {
	// Generate a test key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	encoder, err := NewDPopEncoder(privKey)
	if err != nil {
		t.Fatalf("failed to create encoder: %v", err)
	}

	// Create a custom base transport that tracks if it was called
	var baseTransportCalled bool
	baseTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		baseTransportCalled = true
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
			Header:     make(http.Header),
		}, nil
	})

	transport := &Transport{
		Encoder: encoder,
		Base:    baseTransport,
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)
	_, err = transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if !baseTransportCalled {
		t.Error("custom base transport was not called")
	}
}

// roundTripperFunc is a helper type that implements http.RoundTripper
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
