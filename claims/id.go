package claims

//go:generate go run ../cmd/o2ext-claimgen/main.go claims.json id_claims.gen.go

import (
	"fmt"
	"slices"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
)

type IDTokenValidatorOpts struct {
	// ClientID is the client ID that this token is expected to be issued for.
	// The audience claim will be checked against this. This is required, unless
	// explicitly opted out.
	ClientID *string
	// IgnoreClientID is used to ignore the ClientID check. This is useful for
	// cases where the client ID is not known or is not important.
	IgnoreClientID bool
	// ACRValues is the list of ACR values that are allowed for the token. The
	// token will pass if its ACR claim is present and in the list. If empty, no
	// ACR check is performed.
	ACRValues []string
}

type IDTokenValidator struct {
	opts *IDTokenValidatorOpts
}

func NewIDTokenValidator(opts *IDTokenValidatorOpts) *IDTokenValidator {
	return &IDTokenValidator{opts: opts}
}

func (v *IDTokenValidator) CompactFromToken(token oauth2.Token) (string, error) {
	return token.Extra("id_token").(string), nil
}

func (v *IDTokenValidator) ValidatorOpts() *jwt.ValidatorOpts {
	return &jwt.ValidatorOpts{
		ExpectedAudience: v.opts.ClientID,
		IgnoreAudiences:  v.opts.IgnoreClientID,
	}
}

func (v *IDTokenValidator) Validate(jwt *jwt.VerifiedJWT) (*VerifiedID, error) {
	if len(v.opts.ACRValues) > 0 {
		if !jwt.HasStringClaim("acr") {
			return nil, fmt.Errorf("ACRs requested, but no ACR claim found")
		}
		acr, err := jwt.StringClaim("acr")
		if err != nil {
			return nil, fmt.Errorf("getting ACR claim: %w", err)
		}
		if !slices.Contains(v.opts.ACRValues, acr) {
			return nil, fmt.Errorf("jwt ACR %s not in requested list %v", acr, v.opts.ACRValues)
		}
	}

	return &VerifiedID{jwt: jwt}, nil
}

func NewIDTokenVerifier(provider Provider) (*Verifier[VerifiedID], error) {
	return NewVerifier[VerifiedID](provider)
}
