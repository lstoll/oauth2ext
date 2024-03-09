package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

const DefaultProviderCacheDuration = 15 * time.Minute

type PublicHandle interface {
	PublicHandle(context.Context) (*keyset.Handle, error)
}

type Provider struct {
	Metadata *ProviderMetadata

	overrideHandle PublicHandle

	lastHandle         *keyset.Handle
	lastHandleFetched  time.Time
	lastHandleCacheFor time.Duration
	cacheMu            sync.Mutex
}

type DiscoverOptions struct {
	// CacheDuration indicates how long we cache retrieve metadata/JWK
	// information. Defaults to DefaultProviderCacheDuration.
	CacheDuration time.Duration

	// OverridePublicHandle allows setting an alternate source for the public
	// keyset for this provider. If set, rather than retrieving the JWKS from
	// the provider this function will be called to get a handle to the keyset
	// to verify against. Results from this will not be subject to the normal
	// cache duration for the provider.
	OverridePublicHandle PublicHandle
}

func DiscoverProvider(ctx context.Context, issuer string, opts *DiscoverOptions) (*Provider, error) {
	p := &Provider{
		Metadata:           new(ProviderMetadata),
		lastHandleCacheFor: DefaultProviderCacheDuration,
	}

	if opts != nil {
		if opts.OverridePublicHandle != nil {
			p.overrideHandle = opts.OverridePublicHandle
		}
		if opts.CacheDuration != 0 {
			p.lastHandleCacheFor = opts.CacheDuration
		}
	}

	cfgURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", cfgURL, err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", cfgURL, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status %d from %s, got: %d", http.StatusOK, cfgURL, res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(p.Metadata)
	_ = res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error decoding provider metadata response: %v", err)
	}
	if _, err := p.PublicHandle(ctx); err != nil {
		return nil, fmt.Errorf("getting public keys: %w", err)
	}

	return p, nil
}

func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  p.Metadata.AuthorizationEndpoint,
		TokenURL: p.Metadata.TokenEndpoint,
	}
}

// PublicHandle returns a public handle to the verification keyset for this
// issuer. If there is a cached version within its life it will be returned,
// otherwise it will be refreshed from the provider.
func (p *Provider) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	if p.overrideHandle != nil {
		h, err := p.overrideHandle.PublicHandle(ctx)
		if err != nil {
			return nil, fmt.Errorf("calling overridden public handle: %w", err)
		}
		return h, nil
	}

	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	if p.lastHandle == nil || time.Now().After(p.lastHandleFetched.Add(p.lastHandleCacheFor)) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Metadata.JWKSURI, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request for %s: %w", p.Metadata.JWKSURI, err)
		}
		req = req.WithContext(ctx)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to get keys from %s: %v", p.Metadata.JWKSURI, err)
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
		}
		jwksb, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("reading JWKS body: %w", err)
		}

		h, err := jwt.JWKSetToPublicKeysetHandle(jwksb)
		if err != nil {
			return nil, fmt.Errorf("creating handle from response: %w", err)
		}

		p.lastHandle = h
	}

	return p.lastHandle, nil
}

// VerifyToken is a low-level function that verifies the raw JWT against the
// keyset for this provider. In most cases, one of the higher level ID
// token/access token methods should be used. If the keys need to be refreshed
// they will using the provided context, if that fails we will try anyway with
// the current keyset. It will return the verified JWT contents. This can be
// used against a JWT issued by this provider for any purpose. The validator
// opts should be provided to verify the audience/client ID and other required
// fields.
func (p *Provider) VerifyToken(ctx context.Context, rawJWT string, validatorOpts *jwt.ValidatorOpts) (*jwt.VerifiedJWT, error) {
	h := p.lastHandle
	newH, cacheFetchErr := p.PublicHandle(ctx)
	if cacheFetchErr == nil {
		h = newH
	}

	// we ignore the error for now, and try and verify regardless. if it fails,
	// then we can return the cache error.

	verif, err := jwt.NewVerifier(h)
	if err != nil {
		return nil, fmt.Errorf("creating JWT verifier: %w", err)
	}
	valid, err := jwt.NewValidator(validatorOpts)
	if err != nil {
		return nil, fmt.Errorf("creating JWT validator: %w", err)
	}
	jwt, err := verif.VerifyAndDecode(rawJWT, valid)
	if err != nil {
		err := fmt.Errorf("verifying/decoding JWT: %w", err)
		if cacheFetchErr != nil {
			err = errors.Join(cacheFetchErr, err)
		}
		return nil, err
	}

	return jwt, nil
}

type VerificationOpts struct {
	ClientID       string
	IgnoreClientID bool

	ACRValues []string
}

func (p *Provider) VerifyAccessToken(ctx context.Context, tok *oauth2.Token, opts VerificationOpts) (*AccessTokenClaims, error) {
	var acl AccessTokenClaims
	if err := p.verifyToken(ctx, tok.AccessToken, opts, &acl); err != nil {
		return nil, err
	}
	return &acl, nil
}

func (p *Provider) VerifyIDToken(ctx context.Context, tok *oauth2.Token, opts VerificationOpts) (*IDClaims, error) {
	idt, ok := IDToken(tok)
	if !ok {
		return nil, fmt.Errorf("token does not contain an ID token")
	}
	var idcl IDClaims
	if err := p.verifyToken(ctx, idt, opts, &idcl); err != nil {
		return nil, err
	}
	return &idcl, nil
}

func (p *Provider) verifyToken(ctx context.Context, rawJWT string, opts VerificationOpts, into validatable) error {
	vops := &jwt.ValidatorOpts{
		ExpectedIssuer:  &p.Metadata.Issuer,
		IgnoreAudiences: opts.IgnoreClientID,
	}
	if opts.ClientID != "" {
		vops.ExpectedAudience = &opts.ClientID
	}

	vjwt, err := p.VerifyToken(ctx, rawJWT, vops)
	if err != nil {
		return fmt.Errorf("jwt verification failed: %w", err)
	}

	// TODO(lstoll) is this good enough? Do we want to do more/other processing?
	b, err := vjwt.JSONPayload()
	if err != nil {
		return fmt.Errorf("extracting JSON payload: %w", err)
	}
	if err := json.Unmarshal(b, &into); err != nil {
		return fmt.Errorf("unmarshaling claims: %w", err)
	}

	if len(opts.ACRValues) > 0 && !slices.Contains(opts.ACRValues, into.acr()) {
		return fmt.Errorf("token does not meet ACR requirements")
	}

	return nil
}

func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource) (*IDClaims, error) {
	if p.Metadata.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("provider does not have a userinfo endpoint")
	}

	oc := oauth2.NewClient(ctx, tokenSource)

	req, err := http.NewRequest("GET", p.Metadata.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating identity fetch request: %v", err)
	}

	resp, err := oc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making identity request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication to userinfo endpoint failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("bad response from server: http %d", resp.StatusCode)
	}

	var cl IDClaims

	if err := json.NewDecoder(resp.Body).Decode(&cl); err != nil {
		return nil, fmt.Errorf("failed decoding response body: %v", err)
	}

	// TODO(lstoll) the caller should do this, but is there a way we can as well?
	//
	// make sure the returned userinfo subject matches the token, to prevent
	// token substitution attacks
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

	return &cl, nil
}

type staticPublicHandle struct {
	h *keyset.Handle
}

func (s *staticPublicHandle) PublicHandle(context.Context) (*keyset.Handle, error) {
	return s.h, nil
}

func NewStaticPublicHandle(h *keyset.Handle) PublicHandle {
	return &staticPublicHandle{h: h}
}

type validatable interface {
	acr() string
}

func (c *IDClaims) acr() string {
	return c.ACR
}

func (a *AccessTokenClaims) acr() string {
	return a.ACR
}
