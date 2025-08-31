package jwt

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

type IDTokenVerifier struct {
	Provider       Provider
	OverrideKeyset PublicKeyset

	ClientID       string
	IgnoreClientID bool

	WantAnyACR []string
}

func (i *IDTokenVerifier) Verify(ctx context.Context, token *oauth2.Token) (*IDClaims, error) {
	rawJWT, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found in token")
	}
	return i.VerifyRaw(ctx, rawJWT)
}

func (i *IDTokenVerifier) VerifyRaw(ctx context.Context, rawJWT string) (*IDClaims, error) {
	vopts := verifyOpts{
		Issuer:          i.Provider.Issuer(),
		SupportedAlgs:   algsToJOSEAlgs(i.Provider.SupportedAlgs()),
		WantAnyAudience: jwt.Audience{i.ClientID},
		SkipAudience:    i.IgnoreClientID,
		WantAnyACR:      i.WantAnyACR,
		ValidTimeBuffer: defaultValidTimeBuffer,
	}

	jwt, err := verifyToken(ctx, i.keyset(), rawJWT, vopts)
	if err != nil {
		return nil, fmt.Errorf("verifying id_token: %w", err)
	}

	var cl IDClaims
	if err := jwt.UnmarshalClaims(&cl); err != nil {
		return nil, fmt.Errorf("unmarshalling id_token: %w", err)
	}
	cl.jwt = jwt

	return &cl, nil
}

func (i *IDTokenVerifier) keyset() PublicKeyset {
	if i.OverrideKeyset != nil {
		return i.OverrideKeyset
	}
	return i.Provider.Keyset()
}
