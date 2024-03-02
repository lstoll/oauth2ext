package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lstoll/oidc/discovery"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// PublicKeysetHandleFunc is used to retrieve a handle to the current public tink
// keyset handle. The returned handle should not contain private key material.
// It is called whenever a keyset is required, allowing for implementations to
// rotate the keyset in use as needed.
type PublicKeysetHandleFunc func(ctx context.Context) (*keyset.Handle, error)

// StaticPublicKeysetHandle implements PublicKeysetHandleFunc, with a keyset handle
// that never changes.
func StaticPublicKeysetHandle(h *keyset.Handle) PublicKeysetHandleFunc {
	return func(context.Context) (*keyset.Handle, error) { return h, nil }
}

type Verifier struct {
	md       *discovery.ProviderMetadata
	kshandle PublicKeysetHandleFunc
}

func DiscoverVerifier(ctx context.Context, issuer string) (*Verifier, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	if err := validateHandle(ctx, cl.PublicHandle); err != nil {
		return nil, err
	}

	return &Verifier{
		md:       cl.Metadata(),
		kshandle: cl.PublicHandle,
	}, nil
}

func NewVerifier(issuer string, ph PublicKeysetHandleFunc) *Verifier {
	return &Verifier{
		md: &discovery.ProviderMetadata{
			Issuer: issuer,
		},
		kshandle: ph,
	}
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (v *Verifier) VerifyRaw(ctx context.Context, audience string, raw string, opts ...VerifyOpt) (*Claims, error) {
	h, err := v.kshandle(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting public key handle: %w", err)
	}
	verifier, err := jwt.NewVerifier(h)
	if err != nil {
		return nil, fmt.Errorf("creating jwt verifier: %w", err)
	}

	validator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:   &v.md.Issuer,
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
func validateHandle(ctx context.Context, h PublicKeysetHandleFunc) error {
	ph, err := h(ctx)
	if err != nil {
		return fmt.Errorf("getting handle failed: %w", err)
	}
	if _, err = jwt.NewVerifier(ph); err != nil {
		return fmt.Errorf("creating verifier from handle: %w", err)
	}
	return nil
}
