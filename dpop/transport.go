package dpop

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// Transport is an http.RoundTripper that adds DPoP headers to requests.
type Transport struct {
	// Encoder is used to sign DPoP proofs
	Encoder *DPopEncoder

	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper by adding a DPoP header to the request
// and then calling the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Encoder == nil {
		return nil, fmt.Errorf("dpop: Encoder is nil")
	}

	// Generate DPoP proof with htm and htu claims
	now := time.Now()
	proof, err := t.Encoder.SignAndEncode(&jwt.RawJWTOptions{
		WithoutExpiration: true,
		IssuedAt:          &now,
		CustomClaims: map[string]any{
			"htm": req.Method,
			"htu": req.URL.String(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dpop: failed to create proof: %w", err)
	}

	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())
	req.Header.Set("DPoP", proof)

	// Use the base transport or default
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}
