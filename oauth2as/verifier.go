package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// PublicKeysetHandleFunc is used to retrieve a handle to the current public tink
// keyset handle. The returned handle should not contain private key material.
// It is called whenever a keyset is required, allowing for implementations to
// rotate the keyset in use as needed.
type PublicKeysetHandleFunc func() *keyset.Handle

// StaticPublicKeysetHandle implements PublicKeysetHandleFunc, with a keyset handle
// that never changes.
func StaticPublicKeysetHandle(h *keyset.Handle) PublicKeysetHandleFunc {
	return func() *keyset.Handle { return h }
}

// Verifier can be used to verify ID tokens issued by an OIDC issuer.
type Verifier struct {
	issuer   string
	kshandle PublicKeysetHandleFunc
}

// NewVerifier creates a verfier for the given issuer and keyset.This can be
// constructed from a discovery client.
//
// e.g:
// cl, err := discovery.NewClient(ctx, "http://issuer", discovery.WithBackgroundJWKSRefresh(15*time.Minute))
// NewVerifier(cl.Metadata().Issuer, cl.PublicHandle, ......)
func NewVerifier(issuer string, ph PublicKeysetHandleFunc) *Verifier {
	return &Verifier{
		issuer:   issuer,
		kshandle: ph,
	}
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (v *Verifier) VerifyRaw(ctx context.Context, audience string, raw string, opts ...VerifyOpt) (*Claims, error) {
	verifier, err := jwt.NewVerifier(v.kshandle())
	if err != nil {
		return nil, fmt.Errorf("creating jwt verifier: %w", err)
	}

	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:   &v.issuer,
		ExpectedAudience: &audience,
	})
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}

	verifiedJWT, err := verifier.VerifyAndDecode(raw, validator)
	if err != nil {
		return nil, fmt.Errorf("verifying/decoding jwt: %w", err)
	}

	tb, err := verifiedJWT.JSONPayload()
	if err != nil {
		return nil, fmt.Errorf("getting token JSON payload: %w", err)
	}

	// now parse it in to our type to return
	idt := Claims{}
	if err := json.Unmarshal(tb, &idt); err != nil {
		return nil, fmt.Errorf("unpacking token claims: %v", err)
	}

	return &idt, nil
}

// validateHandle tries to retrieve the current handle and create a verifier,
// used to catch misconfiguration at constructor time rather than use time.
func validateHandle(h PublicKeysetHandleFunc) error {
	if _, err := jwt.NewVerifier(h()); err != nil {
		return fmt.Errorf("creating verifier from handle: %w", err)
	}
	return nil
}
