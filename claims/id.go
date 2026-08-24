package claims

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

// Provider supplies verification keys and ID-token signing metadata.
type Provider interface {
	VerifyJWT(ctx context.Context, compact string, policy jwt.ValidationPolicy) (*jwt.VerifiedJWT, error)
	IDTokenSigningAlgorithms(ctx context.Context) ([]jwt.Algorithm, error)
}

// IDTokenVerifierOpts configures checks that are stable across authentication
// requests.
type IDTokenVerifierOpts struct {
	// ClientID is the client identifier expected in aud and, when present, azp.
	// Exactly one of ClientID and IgnoreClientID must be set.
	ClientID       *string
	IgnoreClientID bool
	// ACRValues restricts acr to one of the requested values when non-empty.
	ACRValues []string
}

// IDTokenSource identifies the endpoint that returned an ID token.
type IDTokenSource uint8

const (
	IDTokenFromTokenEndpoint IDTokenSource = iota + 1
	IDTokenFromAuthorizationEndpoint
)

// IDTokenValidationInput contains values specific to one authentication
// response. Pointer values are cloned before use.
type IDTokenValidationInput struct {
	Source IDTokenSource
	// Exactly one of ExpectedNonce and IgnoreNonce must be set.
	ExpectedNonce *string
	IgnoreNonce   bool
	// MaxAge is the max_age value sent in the authentication request. When set,
	// auth_time is required and checked.
	MaxAge *time.Duration
	// AccessToken and AuthorizationCode are values returned alongside an ID
	// token. They are used to validate at_hash and c_hash.
	AccessToken       *string
	AuthorizationCode *string
}

// IDTokenVerifier validates OpenID Connect ID tokens.
type IDTokenVerifier struct {
	provider Provider
	opts     IDTokenVerifierOpts
}

func NewIDTokenVerifier(provider Provider, opts IDTokenVerifierOpts) (*IDTokenVerifier, error) {
	if provider == nil {
		return nil, fmt.Errorf("claims: provider is required")
	}
	if (opts.ClientID != nil) == opts.IgnoreClientID {
		return nil, fmt.Errorf("claims: exactly one of ClientID and IgnoreClientID must be set")
	}
	if opts.ClientID != nil && *opts.ClientID == "" {
		return nil, fmt.Errorf("claims: ClientID must not be empty")
	}
	cloned := opts
	cloned.ClientID = cloneString(opts.ClientID)
	cloned.ACRValues = slices.Clone(opts.ACRValues)
	return &IDTokenVerifier{provider: provider, opts: cloned}, nil
}

// Verify validates a compact ID token and its authentication-response context.
func (v *IDTokenVerifier) Verify(ctx context.Context, compact string, input IDTokenValidationInput) (*VerifiedID, error) {
	if v == nil || v.provider == nil {
		return nil, fmt.Errorf("claims: invalid ID token verifier")
	}
	if compact == "" {
		return nil, fmt.Errorf("claims: ID token is empty")
	}
	input = cloneIDTokenValidationInput(input)
	if err := input.validate(); err != nil {
		return nil, err
	}
	algorithms, err := v.provider.IDTokenSigningAlgorithms(ctx)
	if err != nil {
		return nil, err
	}
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("claims: provider advertises no supported ID token signing algorithms")
	}
	policy := jwt.ValidationPolicy{
		AllowedAlgorithms: algorithms,
		ClockSkew:         jwt.DefaultClockSkew,
		RequireIssuedAt:   true,
	}
	if v.opts.IgnoreClientID {
		policy.IgnoreAudiences = true
	} else {
		policy.ExpectedAudiences = []string{*v.opts.ClientID}
	}
	verified, err := v.provider.VerifyJWT(ctx, compact, policy)
	if err != nil {
		return nil, err
	}
	id, err := v.validate(verified, input, time.Now())
	if err != nil {
		return nil, verificationErrorf("%v", err)
	}
	return id, nil
}

// VerifyTokenResponse extracts and validates the ID token in an OAuth2 token
// endpoint response. The access token is automatically used for at_hash.
func (v *IDTokenVerifier) VerifyTokenResponse(ctx context.Context, token *oauth2.Token, input IDTokenValidationInput) (*VerifiedID, error) {
	if token == nil {
		return nil, fmt.Errorf("claims: OAuth2 token response is required")
	}
	compact, ok := token.Extra("id_token").(string)
	if !ok || compact == "" {
		return nil, fmt.Errorf("claims: no id_token found in token response")
	}
	if input.Source != 0 && input.Source != IDTokenFromTokenEndpoint {
		return nil, fmt.Errorf("claims: token response ID token source must be the token endpoint")
	}
	input.Source = IDTokenFromTokenEndpoint
	if input.AccessToken == nil && token.AccessToken != "" {
		input.AccessToken = cloneString(&token.AccessToken)
	}
	return v.Verify(ctx, compact, input)
}

func (v *IDTokenVerifier) validate(verified *jwt.VerifiedJWT, input IDTokenValidationInput, now time.Time) (*VerifiedID, error) {
	id := &VerifiedID{VerifiedJWT: verified}
	subject, err := id.Subject()
	if err != nil {
		return nil, fmt.Errorf("claims: ID token subject is required: %w", err)
	}
	if err := validateSubject(subject); err != nil {
		return nil, err
	}
	if !v.opts.IgnoreClientID {
		audiences, err := id.Audiences()
		if err != nil {
			return nil, err
		}
		azp, azpErr := id.AuthorizedParty()
		if len(audiences) > 1 && azpErr != nil {
			return nil, fmt.Errorf("claims: azp is required when an ID token has multiple audiences")
		}
		if azpErr == nil && azp != *v.opts.ClientID {
			return nil, fmt.Errorf("claims: ID token azp does not match the client ID")
		}
	}
	if !input.IgnoreNonce {
		nonce, err := id.Nonce()
		if err != nil {
			return nil, fmt.Errorf("claims: ID token nonce is required: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(nonce), []byte(*input.ExpectedNonce)) != 1 {
			return nil, fmt.Errorf("claims: ID token nonce does not match")
		}
	}
	if input.MaxAge != nil {
		authTime, err := id.AuthTime()
		if err != nil {
			return nil, fmt.Errorf("claims: auth_time is required when max_age was requested: %w", err)
		}
		if authTime.After(now.Add(jwt.DefaultClockSkew)) {
			return nil, fmt.Errorf("claims: ID token auth_time is in the future")
		}
		if now.After(authTime.Add(*input.MaxAge).Add(jwt.DefaultClockSkew)) {
			return nil, fmt.Errorf("claims: maximum authentication age exceeded")
		}
	}
	if len(v.opts.ACRValues) > 0 {
		acr, err := id.ACR()
		if err != nil {
			return nil, fmt.Errorf("claims: ACR was requested but acr is invalid or missing: %w", err)
		}
		if !slices.Contains(v.opts.ACRValues, acr) {
			return nil, fmt.Errorf("claims: ID token acr is not an allowed value")
		}
	}
	algorithm, err := verified.Algorithm()
	if err != nil {
		return nil, err
	}
	if err := validateTokenHash("at_hash", id.HasAtHash(), id.AtHash, input.AccessToken,
		input.Source == IDTokenFromAuthorizationEndpoint && input.AccessToken != nil, algorithm); err != nil {
		return nil, err
	}
	if err := validateTokenHash("c_hash", id.HasCHash(), id.CHash, input.AuthorizationCode,
		input.Source == IDTokenFromAuthorizationEndpoint && input.AuthorizationCode != nil, algorithm); err != nil {
		return nil, err
	}
	return id, nil
}

func validateSubject(subject string) error {
	if subject == "" {
		return fmt.Errorf("claims: ID token subject must not be empty")
	}
	if len(subject) > 255 {
		return fmt.Errorf("claims: ID token subject exceeds 255 ASCII characters")
	}
	for i := range len(subject) {
		if subject[i] > 0x7f {
			return fmt.Errorf("claims: ID token subject must contain only ASCII characters")
		}
	}
	return nil
}

func (input IDTokenValidationInput) validate() error {
	if input.Source != IDTokenFromTokenEndpoint && input.Source != IDTokenFromAuthorizationEndpoint {
		return fmt.Errorf("claims: ID token source is required")
	}
	if (input.ExpectedNonce != nil) == input.IgnoreNonce {
		return fmt.Errorf("claims: exactly one of ExpectedNonce and IgnoreNonce must be set")
	}
	if input.ExpectedNonce != nil && *input.ExpectedNonce == "" {
		return fmt.Errorf("claims: ExpectedNonce must not be empty")
	}
	if input.MaxAge != nil && *input.MaxAge < 0 {
		return fmt.Errorf("claims: MaxAge must not be negative")
	}
	if input.AccessToken != nil && *input.AccessToken == "" {
		return fmt.Errorf("claims: AccessToken must not be empty")
	}
	if input.AuthorizationCode != nil && *input.AuthorizationCode == "" {
		return fmt.Errorf("claims: AuthorizationCode must not be empty")
	}
	return nil
}

func validateTokenHash(name string, present bool, claim func() (string, error), value *string, required bool, algorithm jwt.Algorithm) error {
	if required && !present {
		return fmt.Errorf("claims: %s is required for an ID token returned from the authorization endpoint", name)
	}
	if !present {
		return nil
	}
	if value == nil {
		return nil
	}
	want, err := oidcTokenHash(algorithm, *value)
	if err != nil {
		return err
	}
	got, err := claim()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("claims: ID token %s does not match", name)
	}
	return nil
}

func oidcTokenHash(algorithm jwt.Algorithm, value string) (string, error) {
	var digest []byte
	switch algorithm {
	case jwt.RS256, jwt.PS256, jwt.ES256:
		sum := sha256.Sum256([]byte(value))
		digest = sum[:]
	case jwt.RS384, jwt.PS384, jwt.ES384:
		sum := sha512.Sum384([]byte(value))
		digest = sum[:]
	case jwt.RS512, jwt.PS512, jwt.ES512:
		sum := sha512.Sum512([]byte(value))
		digest = sum[:]
	default:
		return "", fmt.Errorf("claims: signing algorithm %q has no supported OIDC token hash", algorithm)
	}
	return base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2]), nil
}

func cloneIDTokenValidationInput(input IDTokenValidationInput) IDTokenValidationInput {
	input.ExpectedNonce = cloneString(input.ExpectedNonce)
	input.AccessToken = cloneString(input.AccessToken)
	input.AuthorizationCode = cloneString(input.AuthorizationCode)
	if input.MaxAge != nil {
		value := *input.MaxAge
		input.MaxAge = &value
	}
	return input
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
