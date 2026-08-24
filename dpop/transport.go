package dpop

import (
	"fmt"
	"net/http"
	"strings"
)

// Transport is an [http.RoundTripper] that adds DPoP headers to requests.
type Transport struct {
	// Signer is used to sign DPoP proofs
	Signer *Signer

	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip implements [http.RoundTripper] by adding a DPoP header to the
// request and then calling the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Signer == nil {
		return nil, fmt.Errorf("dpop: Signer is nil")
	}

	proofURL := *req.URL
	proofURL.RawQuery = ""
	proofURL.ForceQuery = false
	proofURL.Fragment = ""
	options := ProofOptions{
		HTTPMethod: req.Method,
		HTTPURI:    proofURL.String(),
	}
	if scheme, token, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "DPoP") {
		options.AccessToken = token
	}
	proof, err := t.Signer.SignAndEncode(options)
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to create proof: %w", err)
	}

	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())
	req.Header.Set("DPoP", proof)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}
