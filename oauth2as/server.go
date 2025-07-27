package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as/discovery"
	"github.com/lstoll/oauth2as/internal/oauth2"
	"github.com/lstoll/oauth2as/storage"
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
	// ValidateRedirectURI should confirm if the given redirect is valid for the client. It should
	// compare as per https://tools.ietf.org/html/rfc3986#section-6
	ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error)
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
	Storage storage.Storage
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

// StartAuthorization can be used to handle a request to the auth endpoint. It
// will parse and validate the incoming request, returning a unique identifier.
// If an error was returned, it should be assumed that this has been returned to
// the called appropriately. Otherwise, no response will be written. The caller
// can then use this request to implement the appropriate auth flow. The authID
// should be kept and treated as sensitive - it will be used to mark the request
// as Authorized.
//
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
// https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
func (s *Server) StartAuthorization(w http.ResponseWriter, req *http.Request) {
	authreq, err := oauth2.ParseAuthRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		_ = oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "redirect_uri is in an invalid format", err, "failed to parse redirect URI")
		return
	}

	// If a non valid client ID or redirect URI is specified, we should return
	// an error directly to the user rather than passing it on the redirect.
	//
	// https://tools.ietf.org/html/rfc6749#section-4.1.2.1

	cidok, err := s.config.Clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		_ = oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource check client ID")
		return
	}
	if !cidok {
		_ = oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Client ID is not valid", nil, "")
		return
	}

	redirok, err := s.config.Clients.ValidateClientRedirectURI(authreq.ClientID, authreq.RedirectURI)
	if err != nil {
		_ = oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource redirect URI validation")
		return
	}
	if !redirok {
		_ = oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Invalid redirect URI", nil, "")
		return
	}

	ar := &storage.AuthRequest{
		ID:            uuid.Must(uuid.NewRandom()),
		ClientID:      authreq.ClientID,
		RedirectURI:   redir.String(),
		State:         authreq.State,
		Scopes:        authreq.Scopes,
		Nonce:         authreq.Raw.Get("nonce"),
		CodeChallenge: authreq.CodeChallenge,
		Expiry:        s.now().Add(s.config.AuthValidityTime),
	}
	if authreq.Raw.Get("acr_values") != "" {
		ar.ACRValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}

	switch authreq.ResponseType {
	case oauth2.ResponseTypeCode:
		ar.ResponseType = storage.AuthRequestResponseTypeCode
	default:
		_ = oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeUnsupportedResponseType, authreq.State, "response type must be code", nil)
		return
	}

	if err := s.config.Storage.PutAuthRequest(req.Context(), ar); err != nil {
		_ = oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeErrServerError, authreq.State, "failed to persist session", err)
		return
	}

	areq := &AuthorizationRequest{
		ID:        ar.ID,
		Scopes:    ar.Scopes,
		ClientID:  ar.ClientID,
		ACRValues: ar.ACRValues,
	}
	if authreq.Raw.Get("acr_values") != "" {
		areq.ACRValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}

	// TODO - return parsed request
	// o.handler.StartAuthorization(w, req, areq)
}

type authorizer struct {
	o *Server
}

func (a *authorizer) Authorize(w http.ResponseWriter, r *http.Request, authReqID uuid.UUID, auth *Authorization) error {
	return a.o.finishAuthorization(w, r, authReqID, auth)
}

// TODO - set a authroizer on the handles.
func (s *Server) finishAuthorization(w http.ResponseWriter, req *http.Request, authReqID uuid.UUID, auth *Authorization) error {
	authreq, err := s.config.Storage.GetAuthRequest(req.Context(), authReqID)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get session")
	}
	if authreq == nil {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "session not found in storage")
	}

	if err := s.config.Storage.DeleteAuthRequest(req.Context(), authreq.ID); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "internal error", err, "deleting auth request failed")
	}

	if !slices.Contains(auth.Scopes, oidc.ScopeOpenID) {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "openid scope was not granted")
	}

	stgauth := auth.toStorage(authreq.ID, authreq.ClientID, s.now(), authreq.Nonce)
	if err := s.config.Storage.PutAuthorization(req.Context(), stgauth); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to save authorization")
	}

	switch authreq.ResponseType {
	case storage.AuthRequestResponseTypeCode:
		return s.finishCodeAuthorization(w, req, authreq, stgauth)
	default:
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", authreq.ResponseType))
	}
}

func (s *Server) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, authReq *storage.AuthRequest, auth *storage.Authorization) error {
	ac := &storage.AuthCode{
		ID:              uuid.Must(uuid.NewRandom()),
		AuthorizationID: auth.ID,
		CodeChallenge:   authReq.CodeChallenge,
		Expiry:          s.now().Add(s.config.CodeValidityTime),
	}

	ucode, scode, err := newToken(ac.ID)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to generate code token")
	}

	code, err := marshalToken(ucode)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal code token")
	}

	ac.Code = scode

	if err := s.config.Storage.PutAuthCode(req.Context(), ac); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to save auth code")
	}

	redir, err := url.Parse(authReq.RedirectURI)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to parse authreq's URI")
	}

	codeResp := &oauth2.CodeAuthResponse{
		RedirectURI: redir,
		State:       authReq.State,
		Code:        code,
	}

	oauth2.SendCodeAuthResponse(w, req, codeResp)

	return nil
}

// Token is used to handle the access token endpoint for code flow requests.
// This can handle both the initial access token request, as well as subsequent
// calls for refreshes.
//
// If a handler returns an error, it will be checked and the endpoint will
// respond to the user appropriately. The session will not be invalidated
// automatically, it it the responsibility of the handler to delete if it
// requires this.
// * If the error implements an `Unauthorized() bool` method and the result of
// calling this is true, the caller will be notified of an `invalid_grant`. The
// error text will be returned as the `error_description`
// * All other errors will result an an InternalServerError
//
// This will always return a response to the user, regardless of success or
// failure. As such, once returned the called can assume the HTTP request has
// been dealt with appropriately
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (s *Server) Token(w http.ResponseWriter, req *http.Request) {
	treq, err := oauth2.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	var resp *oauth2.TokenResponse
	switch treq.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		resp, err = s.codeToken(req.Context(), treq)
	case oauth2.GrantTypeRefreshToken:
		resp, err = s.refreshToken(req.Context(), treq)
	default:
		err = &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", treq.GrantType)}
	}
	if err != nil {
		s.logger.WarnContext(req.Context(), "error in token handler", "grant-type", treq.GrantType, "err", err)
		_ = oauth2.WriteError(w, req, err)
		return
	}

	if err := oauth2.WriteTokenResponse(w, resp); err != nil {
		s.logger.ErrorContext(req.Context(), "error writing token response", "grant-type", treq.GrantType, "err", err)
		_ = oauth2.WriteError(w, req, err)
		return
	}
}

func (s *Server) codeToken(ctx context.Context, treq *oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	id, utok, err := unmarshalToken(treq.Code)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	ac, auth, err := s.config.Storage.GetAuthCode(ctx, id) // TODO
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get code from storage", Cause: err}
	}
	if ac == nil || auth == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	// discard the auth code now, it can only be used once regardless of it's
	// validity.
	if err := s.config.Storage.DeleteAuthCode(ctx, id); err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
	}

	// storage should take care of this, but an extra check doesn't hurt
	if s.now().After(ac.Expiry) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(utok, ac.Code)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code", Cause: err}
	}

	// we have a validated code.
	if err := s.validateTokenClient(ctx, treq, auth.ClientID); err != nil {
		return nil, err
	}

	// If the client is public and we require pkce, reject it if there's no
	// verifier.
	reqPKCE, err := s.config.Clients.RequiresPKCE(treq.ClientID)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check if client is public", Cause: err}
	}
	if reqPKCE && treq.CodeVerifier == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, ac.CodeChallenge) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// we have a validated request. Call out to the handler to get the details.
	tr := &TokenRequest{
		Authorization: *auth,
	}

	// TODO - this should be optional
	tresp, err := s.config.TokenHandler(tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return s.buildTokenResponse(ctx, auth, nil, tresp)
}

func (s *Server) refreshToken(ctx context.Context, treq *oauth2.TokenRequest) (_ *oauth2.TokenResponse, retErr error) {
	id, utok, err := unmarshalToken(treq.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}
	rsess, auth, err := s.config.Storage.GetRefreshSession(ctx, id)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get refresh session from storage", Cause: err}
	}
	if rsess == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// queue a delete the session. This is done to ensure each refresh token can only
	// attempt to be used once, regardless of the outcome of the process. The ID
	// is response random to make this a not-usable attack vector. If the refresh
	// succeeds, abort the deferred deletion.
	defer func() {
		if retErr != nil {
			if err := s.config.Storage.DeleteRefreshSession(ctx, rsess.ID); err != nil {
				retErr = &oauth2.HTTPError{
					Code:     http.StatusInternalServerError,
					Message:  "internal error",
					CauseMsg: retErr.Error() + " - subsequent refresh session delete failed",
					Cause:    errors.Join(retErr, err),
				}
			}
		}
	}()

	// storage should take care of this, but an extra check doesn't hurt
	if s.now().After(rsess.Expiry) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(utok, rsess.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok || len(rsess.RefreshToken) == 0 {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code", Cause: err}
	}

	// // we have a validated request. Call out to the handler to get the details.
	// tr := &RefreshTokenRequest{
	// 	Authorization: *auth,
	// }

	// tresp, err := o.handler.RefreshToken(tr)
	// TODO - need to re-do this too.
	tresp, err := s.config.TokenHandler(nil)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return s.buildTokenResponse(ctx, auth, rsess, tresp)
}

// buildTokenResponse creates the oauth token response for code and refresh.
// refreshSession can be nil, if it is and we should issue a refresh token, a
// new refresh session will be created.
func (s *Server) buildTokenResponse(ctx context.Context, auth *storage.Authorization, refreshSess *storage.RefreshSession, tresp *TokenResponse) (*oauth2.TokenResponse, error) {
	var refreshTok string
	if !tresp.OverrideRefreshTokenIssuance && slices.Contains(auth.Scopes, oidc.ScopeOfflineAccess) {
		if refreshSess == nil {
			// code request with refresh allowed, build a new session.
			refreshExpiry := tresp.RefreshTokenValidUntil
			if refreshExpiry.IsZero() {
				refreshExpiry = auth.AuthenticatedAt.Add(s.config.MaxRefreshTime)
			}
			refreshSess = &storage.RefreshSession{
				ID:              uuid.Must(uuid.NewRandom()),
				AuthorizationID: auth.ID,
				Expiry:          refreshExpiry,
			}
		} else {
			// if it is an existing session, only update the expiry if it was
			// overridden.
			if !tresp.RefreshTokenValidUntil.IsZero() {
				refreshSess.Expiry = tresp.RefreshTokenValidUntil
			}
		}

		urefreshtok, srefreshtok, err := newToken(refreshSess.ID)
		if err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}
		}
		refreshSess.RefreshToken = srefreshtok

		refreshTok, err = marshalToken(urefreshtok)
		if err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal refresh token", Cause: err}
		}

		if err := s.config.Storage.PutRefreshSession(ctx, refreshSess); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to update refresh session", Cause: err}
		}
	} else if refreshSess != nil {
		if err := s.config.Storage.DeleteRefreshSession(ctx, refreshSess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete refresh session", Cause: err}
		}
	}

	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = s.now().Add(s.config.IDTokenValidity)
	}
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = s.now().Add(s.config.AccessTokenValidity)
	}

	rawid, rawat, err := s.buildIDAccessTokens(auth, *tresp.Identity, tresp.AccessTokenExtraClaims, idExp, atExp)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "creating raw JWTs", Cause: err}
	}

	h, err := s.config.Keyset.HandleFor(SigningAlgRS256)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "getting handle", Cause: err}
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "creating signer from handle", Cause: err}
	}

	sidt, err := signer.SignAndEncode(rawid)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign id token", Cause: err}
	}

	sat, err := signer.SignAndEncode(rawat)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign access token", Cause: err}
	}

	return &oauth2.TokenResponse{
		AccessToken:  sat,
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    atExp.Sub(s.now()),
		ExtraParams: map[string]interface{}{
			"id_token": string(sidt),
		},
	}, nil
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
