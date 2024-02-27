package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lstoll/oidc/discovery"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

type Verifier struct {
	md *discovery.ProviderMetadata
	ks KeysetSource
}

func DiscoverVerifier(ctx context.Context, issuer string) (*Verifier, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	return &Verifier{
		md: cl.Metadata(),
		ks: cl,
	}, nil
}

func NewVerifier(issuer string, keySource KeysetSource) *Verifier {
	return &Verifier{
		md: &discovery.ProviderMetadata{
			Issuer: issuer,
		},
		ks: keySource,
	}
}

type verifyCfg struct{}

type VerifyOpt func(v *verifyCfg)

func (v *Verifier) VerifyRaw(ctx context.Context, audience string, raw string, opts ...VerifyOpt) (*Claims, error) {
	h, err := v.ks.PublicHandle(ctx)
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
