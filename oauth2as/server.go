package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lstoll/oauth2as/discovery"
	"github.com/lstoll/oauth2as/internal/oauth2"
	"github.com/lstoll/oauth2ext/oidc"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

// ClientSource is used for validating client informantion for the general flow
type ClientSource interface {
	// IsValidClientID should return true if the passed client ID is valid
	IsValidClientID(clientID string) (ok bool, err error)
	// RequiresPKCE indicates if this client is required to use PKCE for token
	// exchange.
	RequiresPKCE(clientID string) (ok bool, err error)
	// ValidateClientSecret should confirm if the passed secret is valid for the
	// given client. If no secret is provided, clientSecret will be empty but
	// this will still be called.
	ValidateClientSecret(clientID, clientSecret string) (ok bool, err error)
	// ValidateRedirectURI should return the list of valid redirect URIs. They
	// will be compared for an exact match, with the exception of loopback
	// addresses, which can have a variable port
	// (https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
	RedirectURIs(clientID string) ([]string, error)
}

const (
	// DefaultAuthValidityTime is used if the AuthValidityTime is not
	// configured.
	DefaultAuthValidityTime = 10 * time.Minute
	// DefaultCodeValidityTime is used if the CodeValidityTime is not
	// configured.
	DefaultCodeValidityTime = 60 * time.Second
	// DefaultIDTokenValidity is the default IDTokenValidity time.
	DefaultIDTokenValidity = 1 * time.Hour
	// DefaultsAccessTokenValidity is the default AccessTokenValdity time.
	DefaultsAccessTokenValidity = 1 * time.Hour
	// DefaultMaxRefreshTime is the default value sessions are refreshable for.
	DefaultMaxRefreshTime = 30 * 24 * time.Hour
)

// Options sets configuration values for the OIDC flow implementation
type Options struct {

	// TODO - do we want to consider splitting the max refresh time, and how
	// long any single refresh token is valid for?

	// Logger can be used to configure a logger that will have errors and
	// warning logged. Defaults to discarding this information.
	Logger *slog.Logger
}

// Server can be used to handle the various parts of the Server auth flow.
type Config struct {
	// Issuer is the issuer we are serving for.
	Issuer string
	// Storage is the storage backend to use for the server.
	Storage Storage
	Clients ClientSource
	Keyset  AlgKeysets

	Logger *slog.Logger

	TokenHandler    func(req *TokenRequest) (*TokenResponse, error)
	UserinfoHandler func(w io.Writer, uireq *UserinfoRequest) (*UserinfoResponse, error)

	// AuthValidityTime is the maximum time an authorization flow/AuthID is
	// valid. This is the time from Starting to Finishing the authorization. The
	// optimal time here will be application specific, and should encompass how
	// long the app expects a user to complete the "upstream" authorization
	// process. Defaults to DefaultAuthValidityTime
	AuthValidityTime time.Duration
	// CodeValidityTime is the maximum time the authorization code is valid,
	// before it is exchanged for a token (code flow). This should be a short
	// value, as the exhange should generally not take long. Defaults to DefaultCodeValidityTime.
	CodeValidityTime time.Duration
	// IDTokenValidity sets the default validity for issued ID tokens. This can
	// be overridden on a per-request basis.
	IDTokenValidity time.Duration
	// AccessTokenValidity sets the default validity for issued access tokens.
	// This can be overridden on a per-request basis. Must be equal or less to
	// the IDTokenValitity time.
	AccessTokenValidity time.Duration
	// MaxRefreshTime sets the longest time a session can be refreshed for, from
	// the time it was created. This can be overridden on a per-request basis.
	// Defaults to DefaultMaxRefreshTime. Any refesh token may be considered
	// valid up until this time.
	MaxRefreshTime time.Duration

	// AuthorizationPath is the path to the authorization endpoint. The server
	// does not handle requests to this, but it is published in the discovery
	// metadata.
	AuthorizationPath string
	TokenPath         string
	UserinfoPath      string

	now func() time.Time
}

type Server struct {
	config Config
	mux    *http.ServeMux

	logger *slog.Logger

	now func() time.Time
}

func NewServer(c Config) (*Server, error) {
	// perform validations
	if c.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	issURL, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer: %w", err)
	}

	if c.Storage == nil {
		return nil, fmt.Errorf("storage is required")
	}
	if c.Clients == nil {
		return nil, fmt.Errorf("clients is required")
	}
	if c.Keyset == nil {
		return nil, fmt.Errorf("keyset is required")
	}

	// TODO - relax this with defaults if we can make them work.
	if c.TokenHandler == nil {
		return nil, fmt.Errorf("token handler is required")
	}
	if c.UserinfoHandler == nil {
		return nil, fmt.Errorf("userinfo handler is required")
	}

	// Set defaults

	if c.AccessTokenValidity == 0 {
		c.AccessTokenValidity = DefaultsAccessTokenValidity
	}
	if c.IDTokenValidity == 0 {
		c.IDTokenValidity = DefaultIDTokenValidity
	}
	if c.AuthValidityTime == 0 {
		c.AuthValidityTime = DefaultAuthValidityTime
	}
	if c.CodeValidityTime == 0 {
		c.CodeValidityTime = DefaultCodeValidityTime
	}
	if c.MaxRefreshTime == 0 {
		c.MaxRefreshTime = DefaultMaxRefreshTime
	}

	svr := &Server{
		config: c,
		mux:    http.NewServeMux(),
		now:    time.Now,
	}

	if c.AuthorizationPath == "" {
		c.AuthorizationPath = DefaultAuthorizationEndpoint
	}
	if c.TokenPath == "" {
		c.TokenPath = DefaultTokenEndpoint
	}

	// Build discovery metadata
	var mdAlgs []string
	for _, k := range c.Keyset.SupportedAlgorithms() {
		mdAlgs = append(mdAlgs, string(k))
	}

	metadata := &oidc.ProviderMetadata{
		Issuer: c.Issuer,
		ResponseTypesSupported: []string{
			"code",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: mdAlgs,
		GrantTypesSupported:              []string{"authorization_code"},
		CodeChallengeMethodsSupported:    []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		JWKSURI:                          issURL.ResolveReference(&url.URL{Path: "/.well-known/jwks.json"}).String(),
		AuthorizationEndpoint:            issURL.ResolveReference(&url.URL{Path: c.AuthorizationPath}).String(),
		TokenEndpoint:                    issURL.ResolveReference(&url.URL{Path: c.TokenPath}).String(),
	}
	if c.UserinfoPath != "" {
		metadata.UserinfoEndpoint = issURL.ResolveReference(&url.URL{Path: c.UserinfoPath}).String()
	}

	discoh, err := discovery.NewConfigurationHandler(metadata, &pubHandle{h: c.Keyset})
	if err != nil {
		return nil, fmt.Errorf("creating configuration handler: %w", err)
	}

	svr.mux.Handle("GET /.well-known/openid-configuration", discoh)
	svr.mux.Handle("GET /.well-known/jwks.json", discoh)

	svr.mux.Handle("POST "+c.TokenPath, http.HandlerFunc(svr.Token))
	if c.UserinfoPath != "" {
		svr.mux.Handle("GET "+c.UserinfoPath, http.HandlerFunc(svr.Userinfo))
	}

	return svr, nil
}

const (
	DefaultAuthorizationEndpoint = "/authorization"
	DefaultTokenEndpoint         = "/token"
	DefaultUserinfoEndpoint      = "/userinfo"
)

// ServeHTTP will handle requests on the following paths:
// * TokenPath
// * UserinfoPath, if configured
// * /.well-known/openid-configuration
// * /.well-known/jwks.json
// TODO - oauth2 discovery endpoint
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mux.ServeHTTP(w, req)
}

func (s *Server) validateTokenClient(_ context.Context, req *oauth2.TokenRequest, wantClientID string) error {
	// check to see if we're working with the same client
	if wantClientID != req.ClientID {
		return &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}

	// validate the client
	cok, err := s.config.Clients.ValidateClientSecret(req.ClientID, req.ClientSecret)
	if err != nil {
		return &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check client id & secret", Cause: err}

	}
	if !cok {
		return &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "Invalid client secret"}
	}

	// TODO - check redirect url. We don't allow wildcards etc, but still worth doing.
	// https://www.rfc-editor.org/rfc/rfc6749#section-10.6

	return nil
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// appropriate response data in JSON format to the passed writer.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (s *Server) Userinfo(w http.ResponseWriter, req *http.Request) {
	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &oauth2.BearerError{} // no content, just request auth
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO - replace this verification logic with oidc.Provider

	// TODO - check the audience is the issuer, as we have hardcoded.

	h, err := s.config.Keyset.HandleFor(SigningAlgRS256)
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}
	ph, err := h.Public()
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	jwtVerifier, err := jwt.NewVerifier(ph)
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	jwtValidator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:     &s.config.Issuer,
		IgnoreAudiences:    true, // we don't care about the audience here, this is just introspecting the user
		ExpectedTypeHeader: ptrOrNil("at+jwt"),
	})
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	jwt, err := jwtVerifier.VerifyAndDecode(authSp[1], jwtValidator)
	if err != nil {
		be := &oauth2.BearerError{Code: oauth2.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	sub, err := jwt.Subject()
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		Subject: sub,
	}

	w.Header().Set("Content-Type", "application/json")

	// TODO - if not set, we should just not handle userinfo.
	uiresp, err := s.config.UserinfoHandler(w, uireq)
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}
	if uiresp.Identity == nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "userinfo has no identity"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO - pre-fill the identity parts that use fixed server values.

	if err := json.NewEncoder(w).Encode(uiresp.Identity); err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}
}

type unauthorizedErr interface {
	error
	Unauthorized() bool
}

func verifyCodeChallenge(codeVerifier, storedCodeChallenge string) bool {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashedVerifier := h.Sum(nil)
	computedChallenge := base64.RawURLEncoding.EncodeToString(hashedVerifier)
	return computedChallenge == storedCodeChallenge
}

func ptrOrNil[T comparable](v T) *T {
	var e T
	if v == e {
		return nil
	}
	return &v
}
