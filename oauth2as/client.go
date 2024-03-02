package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lstoll/oidc/discovery"
	"golang.org/x/oauth2"
)

const (
	// ScopeOfflineAccess requests a refresh token
	ScopeOfflineAccess = "offline_access"
)

type Client struct {
	Verifier

	md *discovery.ProviderMetadata

	o2cfg oauth2.Config

	acrValues  []string
	enforceAcr bool
}

// ClientOpt can be used to customize the client
// nolint:golint
type ClientOpt func(*Client)

// WithAdditionalScopes will set the given scopes on all AuthCode requests. This is in addition to the default "openid" scopes
func WithAdditionalScopes(scopes []string) ClientOpt {
	return func(c *Client) {
		c.o2cfg.Scopes = append(c.o2cfg.Scopes, scopes...)
	}
}

// WithACRValues sets the ACR values to request. If enforce is true, the
// resultant ID token will be checked to make sure it matches one of the
// requested values, and an error will be returned if it doesn't
func WithACRValues(acrValues []string, enforce bool) ClientOpt {
	return func(c *Client) {
		c.acrValues = acrValues
		c.enforceAcr = enforce
	}
}

// DiscoverClient will create a client based on the OIDC discovery of the given
// issuer. It will use the returned information to configure the client, and
// will use it to create a KeySource that discovers published keys as needed.
func DiscoverClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, opts ...ClientOpt) (*Client, error) {
	cl, err := discovery.NewClient(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating discovery client: %v", err)
	}

	return NewClient(cl.Metadata(), cl.PublicHandle, clientID, clientSecret, redirectURL, opts...)
}

// NewClient creates a client directly from the passed in information
func NewClient(md *discovery.ProviderMetadata, ph PublicKeysetHandleFunc, clientID, clientSecret, redirectURL string, opts ...ClientOpt) (*Client, error) {
	if err := validateHandle(context.Background(), ph); err != nil {
		return nil, err
	}

	c := &Client{
		Verifier: Verifier{
			md:       md,
			kshandle: ph,
		},
		md: md,
		o2cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  md.AuthorizationEndpoint,
				TokenURL: md.TokenEndpoint,
			},
			Scopes:      []string{"openid"},
			RedirectURL: redirectURL,
		},
	}

	for _, o := range opts {
		o(c)
	}

	return c, nil
}

type authCodeCfg struct {
	nonce         string
	addlScopes    []string
	codeChallenge string
}

// AuthCodeOption can be used to modify the auth code URL that is generated.
type AuthCodeOption func(*authCodeCfg)

// SetNonce sets the nonce for this request
func SetNonce(nonce string) AuthCodeOption {
	return func(cfg *authCodeCfg) {
		cfg.nonce = nonce
	}
}

// AddScopes adds additional scopes to this URL only
func AddScopes(scopes []string) AuthCodeOption {
	return func(cfg *authCodeCfg) {
		cfg.addlScopes = scopes
	}
}

// AuthCodeWithPKCE generates a PKCE S256 challenge, and writes the verifier to the
// string passed in as codeVerifier. This verifier must be used when the code is
// Exchanged.
func AuthCodeWithPKCE(codeVerifier *string) AuthCodeOption {
	return func(cfg *authCodeCfg) {
		v := generateCodeVerifier()
		cfg.codeChallenge = generateCodeChallenge(v)
		*codeVerifier = v
	}
}

// AuthCodeURL returns the URL the user should be directed to to initiate the
// code auth flow.
func (c *Client) AuthCodeURL(state string, opts ...AuthCodeOption) string {
	accfg := &authCodeCfg{}
	for _, o := range opts {
		o(accfg)
	}

	aopts := []oauth2.AuthCodeOption{}

	if len(c.acrValues) > 0 {
		aopts = append(aopts, oauth2.SetAuthURLParam("acr_values", strings.Join(c.acrValues, " ")))
	}

	if accfg.nonce != "" {
		aopts = append(aopts, oauth2.SetAuthURLParam("nonce", accfg.nonce))
	}

	if accfg.codeChallenge != "" {
		aopts = append(aopts,
			oauth2.SetAuthURLParam("code_challenge", accfg.codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	// copy to avoid modifying the original
	oc := c.o2cfg
	oc.Scopes = append(oc.Scopes, accfg.addlScopes...)

	return oc.AuthCodeURL(state, aopts...)
}

// Token encapsulates the data returned from the token endpoint
type Token struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Claims       Claims    `json:"claims,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

// Valid if it contains an ID token, and the token's claims are in their
// validity period.
func (t *Token) Valid() bool {
	// TODO - nbf claim?
	return t.Claims.Expiry.Time().After(time.Now()) &&
		t.IDToken != ""
}

// Type of the token
func (t *Token) Type() string {
	// only thing we support for now
	return "Bearer"
}

// SetRedirectURL updates the redirect URL this client is configured for.
func (c *Client) SetRedirectURL(redirectURL string) {
	c.o2cfg.RedirectURL = redirectURL
}

// SetClientSecret updates the oauth2 client secret this client is configured for.
func (c *Client) SetClientSecret(secret string) {
	c.o2cfg.ClientSecret = secret
}

type exchangeCfg struct {
	codeVerifier string
}

// ExchangeOptions can be used to customize the code exchange.
type ExchangeOptions func(*exchangeCfg)

// ExchangeWithPKCE performs the code exchange, with the given code verifier.
// The verifier should have been set with the AuthCodeWithPKCE option when
// generating the auth code URL.
func ExchangeWithPKCE(codeVerifier string) ExchangeOptions {
	return func(cfg *exchangeCfg) {
		cfg.codeVerifier = codeVerifier
	}
}

// Exchange the returned code for a set of tokens. If the exchange fails and
// returns an oauth2 error response, the returned error will be an
// `*github.com/parot/oidc/oauth2.TokenError`. If a HTTP error occurs, a
// *HTTPError will be returned.
func (c *Client) Exchange(ctx context.Context, code string, opts ...ExchangeOptions) (*Token, error) {
	ecfg := &exchangeCfg{}
	for _, o := range opts {
		o(ecfg)
	}

	var eopts []oauth2.AuthCodeOption

	if ecfg.codeVerifier != "" {
		eopts = append(eopts, oauth2.SetAuthURLParam("code_verifier", ecfg.codeVerifier))
	}

	t, err := c.o2cfg.Exchange(ctx, code, eopts...)
	if err != nil {
		return nil, parseExchangeError(err)
	}

	return c.oauth2Token(ctx, t)
}

func (c *Client) oauth2Token(ctx context.Context, t *oauth2.Token) (*Token, error) {
	tokraw := t.Extra("id_token")
	raw, ok := tokraw.(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("response did not contain id_token")
	}

	cl, err := c.VerifyRaw(ctx, c.o2cfg.ClientID, raw)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %v", err)
	}

	if c.enforceAcr {
		var found bool
		for _, acr := range c.acrValues {
			if cl.ACR != "" && cl.ACR == acr {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("want one of ACR %v, got %s", c.acrValues, cl.ACR)
		}
	}

	return &Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
		Claims:       *cl,
		IDToken:      raw,
	}, nil
}

type Userinfo struct {
	// Claims wraps the data returned from the endpoint. It should be
	// Unmarshaled into the desired format
	Claims Claims
	// Token returns a new token after this response. This can be used to capture any refreshing that may have taken place.
	Token *Token
}

// Userinfo fetches a set of user information claims from the configured
// userinfo endpoint, provided the provider supports this.
func (c *Client) Userinfo(ctx context.Context, token *Token) (*Userinfo, error) {
	if c.md.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("provider does not have a userinfo endpoint")
	}

	if token.RefreshToken == "" && token.AccessToken == "" {
		return nil, fmt.Errorf("token must have a refresh or access token specified")
	}

	if token.Claims.Subject == "" {
		return nil, fmt.Errorf("token must have claims containing a subject")
	}

	// userinfo is just a HTTP call to the userinfo endpoint, but using the
	// _auth_ rather than ID tokens. just used the wrapped oauth2 client to do
	// this.

	oat := &oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.Type(),
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}

	var roat *oauth2.Token

	oc := oauth2.NewClient(ctx, &captureTS{
		ts: c.o2cfg.TokenSource(ctx, oat),
		notify: func(t *oauth2.Token) {
			roat = t
		},
	})

	req, err := http.NewRequest("GET", c.md.UserinfoEndpoint, nil)
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

	var cl Claims

	if err := json.NewDecoder(resp.Body).Decode(&cl); err != nil {
		return nil, fmt.Errorf("failed decoding response body: %v", err)
	}

	rt := token

	if roat.RefreshToken != token.RefreshToken {
		// Probably refreshed upstream, create a new token to return
		t, err := c.oauth2Token(ctx, roat)
		if err != nil {
			return nil, fmt.Errorf("updated token: %v", err)
		}
		rt = t
	}

	// make sure the returned userinfo subject matches the token, to prevent
	// token substitution attacks
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
	if cl.Subject != token.Claims.Subject {
		return nil, fmt.Errorf("userinfo subject %q does not match token subject %q", cl.Subject, token.Claims.Subject)
	}

	return &Userinfo{
		Claims: cl,
		Token:  rt,
	}, nil
}

type wrapTokenSource struct {
	ts oauth2.TokenSource
	c  *Client
}

func (c *Client) TokenSource(ctx context.Context, t *Token) TokenSource {
	o2tok := &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		Expiry:       t.Expiry,
	}

	return &wrapTokenSource{
		ts: c.o2cfg.TokenSource(ctx, o2tok),
		c:  c,
	}
}

func (w *wrapTokenSource) Token(ctx context.Context) (*Token, error) {
	o2tok, err := w.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("getting oauth2 token: %v", err)
	}

	return w.c.oauth2Token(ctx, o2tok)
}

type captureTS struct {
	ts     oauth2.TokenSource
	notify func(t *oauth2.Token)
}

func (c *captureTS) Token() (*oauth2.Token, error) {
	t, err := c.ts.Token()
	if err != nil {
		return nil, err
	}
	c.notify(t)
	return t, nil
}

func generateCodeVerifier() string {
	randomBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		panic(err) // this should never fail in a recoverable way
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	hashed := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hashed)
}
