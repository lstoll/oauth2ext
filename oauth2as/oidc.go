package oidcop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oidc"
	"github.com/lstoll/oidcop/discovery"
	"github.com/lstoll/oidcop/internal/oauth2"
	"github.com/lstoll/oidcop/storage"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// HandleFn is used to get a tink handle for a keyset, when it is needed.
type HandleFn func(context.Context) (*keyset.Handle, error)

// StaticHandleFn is a convenience method to create a HandleFn from a fixed
// keyset handle.
func StaticHandleFn(h *keyset.Handle) HandleFn {
	return HandleFn(func(context.Context) (*keyset.Handle, error) { return h, nil })
}

// SigningAlg represents supported JWT signing algorithms
type SigningAlg string

const (
	SigningAlgRS256 = "RS256"
	SigningAlgES256 = "ES256"
)

func (s SigningAlg) Template() *tinkpb.KeyTemplate {
	switch s {
	case SigningAlgRS256:
		return jwt.RS256_2048_F4_Key_Template()
	case SigningAlgES256:
		return jwt.ES256Template()
	default:
		panic(fmt.Sprintf("invalid signing alg %s", s))
	}
}

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
	// Issuer is the issuer we are serving for.
	Issuer string
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
	// be overriden on a per-request basis.
	IDTokenValidity time.Duration
	// AccessTokenValidity sets the default validity for issued access tokens.
	// This can be overriden on a per-request basis. Must be equal or less to
	// the IDTokenValitity time.
	AccessTokenValidity time.Duration
	// MaxRefreshTime sets the longest time a session can be refreshed for, from
	// the time it was created. This can be overriden on a per-request basis.
	// Defaults to DefaultMaxRefreshTime. Any refesh token may be considered
	// valid up until this time.
	MaxRefreshTime time.Duration

	// TODO - do we want to consider splitting the max refresh time, and how
	// long any single refresh token is valid for?

	// Logger can be used to configure a logger that will have errors and
	// warning logged. Defaults to discarding this information.
	Logger *slog.Logger
}

// OIDC can be used to handle the various parts of the OIDC auth flow.
type OIDC struct {
	issuer  string
	storage storage.Storage
	clients ClientSource
	keyset  map[SigningAlg]HandleFn
	handler AuthHandlers
	opts    Options
	logger  *slog.Logger

	now func() time.Time
}

func New(issuer string, storage storage.Storage, clientSource ClientSource, keyset map[SigningAlg]HandleFn, handlers AuthHandlers, opts *Options) (*OIDC, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer must be provided")
	}
	if opts == nil {
		opts = &Options{}
	}

	if _, ok := keyset[SigningAlgRS256]; !ok {
		return nil, errors.New("keyset must contain a RS256 handle")
	}

	o := &OIDC{
		issuer:  issuer,
		storage: storage,
		clients: clientSource,
		handler: handlers,
		keyset:  keyset,

		opts: *opts,

		now:    time.Now,
		logger: opts.Logger,
	}

	if o.logger == nil {
		o.logger = slog.New(&discardHandler{})
	}

	if o.opts.AuthValidityTime == time.Duration(0) {
		o.opts.AuthValidityTime = DefaultAuthValidityTime
	}
	if o.opts.CodeValidityTime == time.Duration(0) {
		o.opts.CodeValidityTime = DefaultCodeValidityTime
	}
	if o.opts.IDTokenValidity == time.Duration(0) {
		o.opts.IDTokenValidity = DefaultIDTokenValidity
	}
	if o.opts.AccessTokenValidity == time.Duration(0) {
		o.opts.AccessTokenValidity = DefaultsAccessTokenValidity
	}
	if o.opts.MaxRefreshTime == time.Duration(0) {
		o.opts.MaxRefreshTime = DefaultMaxRefreshTime
	}

	if o.opts.AccessTokenValidity < o.opts.IDTokenValidity {
		return nil, fmt.Errorf("ID token validity must be equal or greater to the access token validity period")
	}

	handlers.SetAuthorizer(&authorizer{o: o})

	return o, nil
}

func (o *OIDC) BuildDiscovery() *oidc.ProviderMetadata {
	var algs []string
	for k := range o.keyset {
		algs = append(algs, string(k))
	}
	return &oidc.ProviderMetadata{
		Issuer: o.issuer,
		ResponseTypesSupported: []string{
			"code",
			// TODO - we "must" support these, but we don't currently.
			// "id_token",
			// "id_token token",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: algs,
		GrantTypesSupported:              []string{"authorization_code"},
		CodeChallengeMethodsSupported:    []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		JWKSURI:                          o.issuer + "/.well-known/jwks.json",
	}
}

const (
	DefaultAuthorizationEndpoint = "/authorization"
	DefaultTokenEndpoint         = "/token"
	DefaultUserinfoEndpoint      = "/userinfo"
)

// AttachHandlers will bind handlers for the following endpoints to the given
// mux. If the provided metadata specifies a URL for them already it will be
// used, if not defaults will be set. If metadata is nil, BuildDiscovery will be
// used.
func (o *OIDC) AttachHandlers(mux *http.ServeMux, metadata *oidc.ProviderMetadata) error {
	if metadata == nil {
		metadata = o.BuildDiscovery()
	}
	if metadata.AuthorizationEndpoint == "" {
		metadata.AuthorizationEndpoint = o.issuer + DefaultAuthorizationEndpoint
	}
	authEndpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", metadata.AuthorizationEndpoint, err)
	}
	if metadata.TokenEndpoint == "" {
		metadata.TokenEndpoint = o.issuer + DefaultTokenEndpoint
	}
	tokenEndpoint, err := url.Parse(metadata.TokenEndpoint)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", metadata.TokenEndpoint, err)
	}
	if metadata.UserinfoEndpoint == "" {
		metadata.UserinfoEndpoint = o.issuer + DefaultUserinfoEndpoint
	}
	userinfoEndpoint, err := url.Parse(metadata.UserinfoEndpoint)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", metadata.UserinfoEndpoint, err)
	}

	discoh, err := discovery.NewConfigurationHandler(metadata, &pubHandle{h: o.keyset[SigningAlgRS256]})
	if err != nil {
		return fmt.Errorf("creating configuration handler: %w", err)
	}

	mux.Handle("GET /.well-known/openid-configuration", discoh)
	mux.Handle("GET /.well-known/jwks.json", discoh)

	mux.Handle("GET "+authEndpoint.Path, http.HandlerFunc(o.StartAuthorization))
	mux.Handle("POST "+tokenEndpoint.Path, http.HandlerFunc(o.Token))
	mux.Handle("GET "+userinfoEndpoint.Path, http.HandlerFunc(o.Userinfo))

	return nil
}

type pubHandle struct {
	// TODO - either convert oidc to handle func, or decide to keep it an
	// interface.
	h HandleFn
}

func (p *pubHandle) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	h, err := p.h(ctx)
	if err != nil {
		return nil, err
	}
	pub, err := h.Public()
	if err != nil {
		return nil, err
	}
	return pub, nil
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
func (o *OIDC) StartAuthorization(w http.ResponseWriter, req *http.Request) {
	authreq, err := oauth2.ParseAuthRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "redirect_uri is in an invalid format", err, "failed to parse redirect URI")
		return
	}

	// If a non valid client ID or redirect URI is specified, we should return
	// an error directly to the user rather than passing it on the redirect.
	//
	// https://tools.ietf.org/html/rfc6749#section-4.1.2.1

	cidok, err := o.clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource check client ID")
		return
	}
	if !cidok {
		oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Client ID is not valid", nil, "")
		return
	}

	redirok, err := o.clients.ValidateClientRedirectURI(authreq.ClientID, authreq.RedirectURI)
	if err != nil {
		oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource redirect URI validation")
		return
	}
	if !redirok {
		oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Invalid redirect URI", nil, "")
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
		Expiry:        o.now().Add(o.opts.AuthValidityTime),
	}
	if authreq.Raw.Get("acr_values") != "" {
		ar.ACRValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}

	switch authreq.ResponseType {
	case oauth2.ResponseTypeCode:
		ar.ResponseType = storage.AuthRequestResponseTypeCode
	default:
		oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeUnsupportedResponseType, authreq.State, "response type must be code", nil)
		return
	}

	if err := o.storage.PutAuthRequest(req.Context(), ar); err != nil {
		oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeErrServerError, authreq.State, "failed to persist session", err)
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

	o.handler.StartAuthorization(w, req, areq)
}

type authorizer struct {
	o *OIDC
}

func (a *authorizer) Authorize(w http.ResponseWriter, r *http.Request, authReqID uuid.UUID, auth *Authorization) error {
	return a.o.finishAuthorization(w, r, authReqID, auth)
}

// TODO - set a authroizer on the handles.
func (o *OIDC) finishAuthorization(w http.ResponseWriter, req *http.Request, authReqID uuid.UUID, auth *Authorization) error {
	authreq, err := o.storage.GetAuthRequest(req.Context(), authReqID)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get session")
	}
	if authreq == nil {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "session not found in storage")
	}

	if err := o.storage.DeleteAuthRequest(req.Context(), authreq.ID); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "internal error", err, "deleting auth request failed")
	}

	if !slices.Contains(auth.Scopes, oidc.ScopeOpenID) {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "openid scope was not granted")
	}

	stgauth := auth.toStorage(authreq.ID, authreq.ClientID, o.now(), authreq.Nonce)
	if err := o.storage.PutAuthorization(req.Context(), stgauth); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to save authorization")
	}

	switch authreq.ResponseType {
	case storage.AuthRequestResponseTypeCode:
		return o.finishCodeAuthorization(w, req, authreq, stgauth)
	default:
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", authreq.ResponseType))
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, authReq *storage.AuthRequest, auth *storage.Authorization) error {
	ac := &storage.AuthCode{
		ID:              uuid.Must(uuid.NewRandom()),
		AuthorizationID: auth.ID,
		CodeChallenge:   authReq.CodeChallenge,
		Expiry:          o.now().Add(o.opts.CodeValidityTime),
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

	if err := o.storage.PutAuthCode(req.Context(), ac); err != nil {
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
func (o *OIDC) Token(w http.ResponseWriter, req *http.Request) {
	treq, err := oauth2.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	var resp *oauth2.TokenResponse
	switch treq.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		resp, err = o.codeToken(req.Context(), treq)
	case oauth2.GrantTypeRefreshToken:
		resp, err = o.refreshToken(req.Context(), treq)
	default:
		err = &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", treq.GrantType)}
	}
	if err != nil {
		o.logger.WarnContext(req.Context(), "error in token handler", "grant-type", treq.GrantType, "err", err)
		_ = oauth2.WriteError(w, req, err)
		return
	}

	if err := oauth2.WriteTokenResponse(w, resp); err != nil {
		o.logger.ErrorContext(req.Context(), "error writing token repsonse", "grant-type", treq.GrantType, "err", err)
		_ = oauth2.WriteError(w, req, err)
		return
	}
}

func (o *OIDC) codeToken(ctx context.Context, treq *oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	id, utok, err := unmarshalToken(treq.Code)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	ac, auth, err := o.storage.GetAuthCode(ctx, id) // TODO
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get code from storage", Cause: err}
	}
	if ac == nil || auth == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	// discard the auth code now, it can only be used once regardless of it's
	// validity.
	if err := o.storage.DeleteAuthCode(ctx, id); err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
	}

	// storage should take care of this, but an extra check doesn't hurt
	if o.now().After(ac.Expiry) {
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
	if err := o.validateTokenClient(ctx, treq, auth.ClientID); err != nil {
		return nil, err
	}

	// If the client is public and we require pkce, reject it if there's no
	// verifier.
	reqPKCE, err := o.clients.RequiresPKCE(treq.ClientID)
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

	tresp, err := o.handler.Token(tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return o.buildTokenResponse(ctx, auth, nil, tresp)
}

func (o *OIDC) refreshToken(ctx context.Context, treq *oauth2.TokenRequest) (_ *oauth2.TokenResponse, retErr error) {
	id, utok, err := unmarshalToken(treq.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}
	rsess, auth, err := o.storage.GetRefreshSession(ctx, id)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get refresh session from storage", Cause: err}
	}
	if rsess == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// queue a delete the session. This is done to ensure each refresh token can only
	// attempt to be used once, regardless of the outcome of the process. The ID
	// is sufficently random to make this a not-usable attack vector. If the refresh
	// succeeds, abort the deferred deletion.
	defer func() {
		if retErr != nil {
			if err := o.storage.DeleteRefreshSession(ctx, rsess.ID); err != nil {
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
	if o.now().After(rsess.Expiry) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(utok, rsess.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok || len(rsess.RefreshToken) == 0 {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code", Cause: err}
	}

	// we have a validated request. Call out to the handler to get the details.
	tr := &RefreshTokenRequest{
		Authorization: *auth,
	}

	tresp, err := o.handler.RefreshToken(tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return o.buildTokenResponse(ctx, auth, rsess, tresp)
}

// buildTokenResponse creates the oauth token response for code and refresh.
// refreshSession can be nil, if it is and we should issue a refresh token, a
// new refresh session will be created.
func (o *OIDC) buildTokenResponse(ctx context.Context, auth *storage.Authorization, refreshSess *storage.RefreshSession, tresp *TokenResponse) (*oauth2.TokenResponse, error) {
	var refreshTok string
	if !tresp.OverrideRefreshTokenIssuance && slices.Contains(auth.Scopes, oidc.ScopeOfflineAccess) {
		if refreshSess == nil {
			// code request with refresh allowed, build a new session.
			refreshExpiry := tresp.RefreshTokenValidUntil
			if refreshExpiry.IsZero() {
				refreshExpiry = auth.AuthenticatedAt.Add(o.opts.MaxRefreshTime)
			}
			refreshSess = &storage.RefreshSession{
				ID:              uuid.Must(uuid.NewRandom()),
				AuthorizationID: auth.ID,
				Expiry:          refreshExpiry,
			}
		} else {
			// if it is an existing session, only update the expiry if it was
			// overriden.
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

		if err := o.storage.PutRefreshSession(ctx, refreshSess); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to update refresh session", Cause: err}
		}
	} else if refreshSess != nil {
		if err := o.storage.DeleteRefreshSession(ctx, refreshSess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete refresh session", Cause: err}
		}
	}

	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = o.now().Add(o.opts.IDTokenValidity)
	}
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = o.now().Add(o.opts.AccessTokenValidity)
	}

	rawid, rawat, err := o.buildIDAccessTokens(auth, *tresp.Identity, tresp.AccessTokenExtraClaims, idExp, atExp)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "creating raw JWTs", Cause: err}
	}

	h, err := o.keyset[SigningAlgRS256](ctx)
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
		ExpiresIn:    atExp.Sub(o.now()),
		ExtraParams: map[string]interface{}{
			"id_token": string(sidt),
		},
	}, nil
}

func (o *OIDC) validateTokenClient(_ context.Context, req *oauth2.TokenRequest, wantClientID string) error {
	// check to see if we're working with the same client
	if wantClientID != req.ClientID {
		return &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}

	// validate the client
	cok, err := o.clients.ValidateClientSecret(req.ClientID, req.ClientSecret)
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
func (o *OIDC) Userinfo(w http.ResponseWriter, req *http.Request) {
	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &oauth2.BearerError{} // no content, just request auth
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO - replace this verification logic with oidc.Provider

	// TODO - check the audience is the issuer, as we have hardcoded.

	h, err := o.keyset[SigningAlgRS256](req.Context())
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
		ExpectedIssuer:     &o.issuer,
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

	uiresp, err := o.handler.Userinfo(w, uireq)
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
