package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
)

// jwtTYPAccessToken is the type header for OAuth2 JWT Access tokens.
//
// https://datatracker.ietf.org/doc/html/rfc9068#name-header
const jwtTYPAccessToken = "at+jwt"

const DefaultCacheDuration = 10 * time.Minute

type Provider struct {
	Metadata      Metadata
	HTTPClient    *http.Client
	CacheDuration time.Duration

	cacheMu          sync.Mutex
	cacheLastFetched time.Time
	cachedHandle     *keyset.Handle

	oidcDiscoveryURL string
}

var _ jwt.Verifier = (*Provider)(nil)

// Endpoint returns the OAuth2 endpoint configuration for this provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  p.Metadata.authorizationEndpoint(),
		TokenURL: p.Metadata.tokenEndpoint(),
	}
}

func (p *Provider) JWKSHandle(ctx context.Context) (*keyset.Handle, error) {
	if err := p.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}
	return p.cachedHandle, nil
}

func (p *Provider) VerifyAndDecode(compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	handle, err := p.JWKSHandle(context.Background())
	if err != nil {
		return nil, err
	}
	verif, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}
	jwt, err := verif.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, err
	}
	// perform an additional check, we should only ever pass tokens from the
	// issuer.
	iss, err := jwt.Issuer()
	if err != nil {
		return nil, fmt.Errorf("getting issuer: %w", err)
	}
	if iss != p.Metadata.issuer() {
		return nil, fmt.Errorf("invalid issuer: got %q, want %q", iss, p.Metadata.issuer())
	}

	return jwt, nil
}

type IDTokenValidatorOpts struct {
	ClientID       *string
	IgnoreClientID bool
}

type IDTokenValidator struct {
	tink *jwt.Validator
}

func (p *Provider) NewIDTokenValidator(opts *IDTokenValidatorOpts) (*IDTokenValidator, error) {
	if opts == nil {
		opts = &IDTokenValidatorOpts{}
	}
	vo := &jwt.ValidatorOpts{
		ExpectedIssuer:   ptr(p.Metadata.issuer()),
		ExpectedAudience: opts.ClientID,
		IgnoreAudiences:  opts.IgnoreClientID,
	}
	tv, err := jwt.NewValidator(vo)
	if err != nil {
		return nil, fmt.Errorf("creating tink validator: %w", err)
	}
	return &IDTokenValidator{tink: tv}, nil
}

func (p *Provider) VerifyAndDecodeIDToken(token *oauth2.Token, validator *IDTokenValidator) (*jwt.VerifiedJWT, error) {
	rawJWT, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found in token")
	}
	// TODO - additional checks here.
	j, err := p.VerifyAndDecode(rawJWT, validator.tink)
	if err != nil {
		return nil, err
	}
	return j, nil
}

type AccessTokenValidatorOpts struct {
	ClientID       *string
	IgnoreClientID bool
}

type AccessTokenValidator struct {
	tink *jwt.Validator
}

func (p *Provider) NewAccessTokenValidator(opts *AccessTokenValidatorOpts) (*AccessTokenValidator, error) {
	vo := &jwt.ValidatorOpts{
		ExpectedIssuer:     ptr(p.Metadata.issuer()),
		ExpectedTypeHeader: ptr(jwtTYPAccessToken),
		ExpectedAudience:   opts.ClientID,
		IgnoreAudiences:    opts.IgnoreClientID,
	}
	tv, err := jwt.NewValidator(vo)
	if err != nil {
		return nil, fmt.Errorf("creating tink validator: %w", err)
	}
	return &AccessTokenValidator{tink: tv}, nil
}

func (p *Provider) VerifyAndDecodeAccessToken(token *oauth2.Token, validator *AccessTokenValidator) (*jwt.VerifiedJWT, error) {
	j, err := p.VerifyAndDecode(token.AccessToken, validator.tink)
	if err != nil {
		return nil, err
	}
	// TODO - add our additional checks here.
	return j, nil
}

// Userinfo will use the token source to query the userinfo endpoint of the
// provider. It will unmarshal the response in to the provided into.
func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource, into any) error {
	if p.Metadata.userinfoEndpoint() == "" {
		return fmt.Errorf("provider does not support userinfo endpoint")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, internal.HTTPClientFromContext(ctx, p.HTTPClient))

	client := oauth2.NewClient(ctx, tokenSource)
	res, err := client.Get(p.Metadata.userinfoEndpoint())
	if err != nil {
		return fmt.Errorf("getting userinfo: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo request failed with code %d", res.StatusCode)
	}

	if res.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("userinfo response has unexpected content type: %s", res.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading userinfo response: %w", err)
	}

	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("unmarshalling userinfo response: %w", err)
	}

	return nil
}

func ptr[T any](v T) *T {
	return &v
}
