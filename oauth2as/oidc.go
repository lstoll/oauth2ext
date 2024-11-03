package oidcop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidcop/internal"
	"github.com/lstoll/oidcop/internal/oauth2"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// KeysetHandle is used to get the current handle for a signing keyset. It
// should contain private key material suitable for JWT signing
type KeysetHandle interface {
	Handle(context.Context) (*keyset.Handle, error)
}

type staticKeysetHandle struct {
	h *keyset.Handle
}

func (s *staticKeysetHandle) Handle(context.Context) (*keyset.Handle, error) {
	return s.h, nil
}

func NewStaticKeysetHandle(h *keyset.Handle) KeysetHandle {
	return &staticKeysetHandle{h: h}
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
	DefaultAuthValidityTime = 1 * time.Hour
	// DefaultCodeValidityTime is used if the CodeValidityTime is not
	// configured.
	DefaultCodeValidityTime = 60 * time.Second
)

// Config sets configuration values for the OIDC flow implementation
type Config struct {
	// Issuer is the issuer we are serving for.
	Issuer string
	// AuthValidityTime is the maximum time an authorization flow/AuthID is
	// valid. This is the time from Starting to Finishing the authorization. The
	// optimal time here will be application specific, and should encompass how
	// long the app expects a user to complete the "upstream" authorization
	// process.
	AuthValidityTime time.Duration
	// CodeValidityTime is the maximum time the authorization code is valid,
	// before it is exchanged for a token (code flow). This should be a short
	// value, as the exhange should generally not take long
	CodeValidityTime time.Duration
}

type OIDCOpt func(*OIDC)

// OIDC can be used to handle the various parts of the OIDC auth flow.
type OIDC struct {
	issuer       string
	smgr         SessionManager
	clients      ClientSource
	keysetHandle KeysetHandle

	authValidityTime time.Duration
	codeValidityTime time.Duration

	now func() time.Time
}

func New(cfg *Config, smgr SessionManager, clientSource ClientSource, keysetHandle KeysetHandle, opts ...OIDCOpt) (*OIDC, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer must be provided")
	}

	o := &OIDC{
		smgr:         smgr,
		clients:      clientSource,
		keysetHandle: keysetHandle,

		issuer:           cfg.Issuer,
		authValidityTime: cfg.AuthValidityTime,
		codeValidityTime: cfg.CodeValidityTime,

		now: time.Now,
	}

	for _, opt := range opts {
		opt(o)
	}

	if o.authValidityTime == time.Duration(0) {
		o.authValidityTime = DefaultAuthValidityTime
	}
	if o.codeValidityTime == time.Duration(0) {
		o.codeValidityTime = DefaultCodeValidityTime
	}

	return o, nil
}

// AuthorizationRequest details the information the user starting the
// authorization flow requested
type AuthorizationRequest struct {
	// SessionID that was generated for this session. This should be tracked
	// throughout the authentication process
	SessionID string
	// ACRValues are the authentication context class reference values the
	// caller requested
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
	ACRValues []string
	// Scopes that have been requested
	Scopes []string
	// ClientID that started this request
	ClientID string
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
func (o *OIDC) StartAuthorization(w http.ResponseWriter, req *http.Request) (*AuthorizationRequest, error) {
	authreq, err := oauth2.ParseAuthRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return nil, fmt.Errorf("failed to parse auth endpoint request: %w", err)
	}

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		return nil, oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "redirect_uri is in an invalid format", err, "failed to parse redirect URI")
	}

	// If a non valid client ID or redirect URI is specified, we should return
	// an error directly to the user rather than passing it on the redirect.
	//
	// https://tools.ietf.org/html/rfc6749#section-4.1.2.1

	cidok, err := o.clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		return nil, oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource check client ID")
	}
	if !cidok {
		return nil, oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Client ID is not valid", nil, "")
	}

	redirok, err := o.clients.ValidateClientRedirectURI(authreq.ClientID, authreq.RedirectURI)
	if err != nil {
		return nil, oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "error calling clientsource redirect URI validation")
	}
	if !redirok {
		return nil, oauth2.WriteHTTPError(w, req, http.StatusBadRequest, "Invalid redirect URI", nil, "")
	}

	ar := &sessAuthRequest{
		RedirectURI:   redir.String(),
		State:         authreq.State,
		Scopes:        authreq.Scopes,
		Nonce:         authreq.Raw.Get("nonce"),
		CodeChallenge: authreq.CodeChallenge,
	}

	switch authreq.ResponseType {
	case oauth2.ResponseTypeCode:
		ar.ResponseType = authRequestResponseTypeCode
	default:
		return nil, oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeUnsupportedResponseType, authreq.State, "response type must be code", nil)
	}

	sess := &sessionV2{
		ID:       o.smgr.NewID(),
		Stage:    sessionStageRequested,
		ClientID: authreq.ClientID,
		Request:  ar,
		Expiry:   o.now().Add(o.authValidityTime),
	}

	if err := putSession(req.Context(), o.smgr, sess); err != nil {
		return nil, oauth2.WriteAuthError(w, req, redir, oauth2.AuthErrorCodeErrServerError, authreq.State, "failed to persist session", err)
	}

	areq := &AuthorizationRequest{
		SessionID: sess.ID,
		Scopes:    authreq.Scopes,
		ClientID:  authreq.ClientID,
	}
	if authreq.Raw.Get("acr_values") != "" {
		areq.ACRValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}
	return areq, nil
}

// Authorization tracks the information a session was actually authorized for
type Authorization struct {
	// Scopes are the list of scopes this session was granted
	Scopes []string
	// ACR is the Authentication Context Class Reference the session was
	// authenticated with
	ACR string
	// AMR are the Authentication Methods Reference the session was
	// authenticated with
	AMR []string
}

// FinishAuthorization should be called once the consumer has validated the
// identity of the user. This will return the appropriate response directly to
// the passed http context, which should be considered finalized when this is
// called. Note: This does not have to be the same http request in which
// Authorization was started, but the session ID field will need to be tracked and
// consistent.
//
// The scopes this request has been granted with should be included. Metadata
// can be passed, that will be made available to requests to userinfo and token
// issue/refresh. This is application-specific, and should be used to track
// information needed to serve those endpoints.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func (o *OIDC) FinishAuthorization(w http.ResponseWriter, req *http.Request, sessionID string, auth *Authorization) error {
	sess, err := getSession(req.Context(), o.smgr, sessionID)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to get session")
	}
	if sess == nil {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "session not found in storage")
	}

	var openidScope bool
	for _, s := range auth.Scopes {
		if s == "openid" {
			openidScope = true
		}
	}
	if !openidScope {
		return oauth2.WriteHTTPError(w, req, http.StatusForbidden, "Access Denied", err, "openid scope was not granted")

	}

	sess.Authorization = &sessAuthorization{
		Scopes:       auth.Scopes,
		ACR:          auth.ACR,
		AMR:          auth.AMR,
		AuthorizedAt: o.now(),
	}

	switch sess.Request.ResponseType {
	case authRequestResponseTypeCode:
		return o.finishCodeAuthorization(w, req, sess)
	default:
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", nil, fmt.Sprintf("unknown ResponseType %s", sess.Request.ResponseType))
	}
}

func (o *OIDC) finishCodeAuthorization(w http.ResponseWriter, req *http.Request, session *sessionV2) error {
	codeExp := o.now().Add(o.codeValidityTime)

	ucode, scode, err := newToken(session.ID, codeExp)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to generate code token")
	}

	code, err := marshalToken(ucode)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to marshal code token")
	}

	session.AuthCode = scode
	session.Stage = sessionStageCode
	// switch expiry to the max lifetime of the code
	session.Expiry = codeExp

	if err := putSession(req.Context(), o.smgr, session); err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to put authReq to storage")
	}

	redir, err := url.Parse(session.Request.RedirectURI)
	if err != nil {
		return oauth2.WriteHTTPError(w, req, http.StatusInternalServerError, "internal error", err, "failed to parse authreq's URI")
	}

	codeResp := &oauth2.CodeAuthResponse{
		RedirectURI: redir,
		State:       session.Request.State,
		Code:        code,
	}

	oauth2.SendCodeAuthResponse(w, req, codeResp)

	return nil
}

// TokenRequest encapsulates the information from the request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// SessionID of the session this request corresponds to
	SessionID string
	// ClientID of the client this session is bound to.
	ClientID string
	// Authorization information this session was authorized with
	Authorization Authorization
	// GrantType indicates the grant that was requested for this invocation of
	// the token endpoint
	GrantType oauth2.GrantType
	// SessionRefreshable is true if the offline_access scope was permitted for
	// the user, i.e this session should issue refresh tokens
	SessionRefreshable bool
	// IsRefresh is true if the token endpoint was called with the refresh token
	// grant (i.e called with a refresh, rather than access token)
	IsRefresh bool
	// Nonce from the authentication request, if specified
	Nonce string
	// AuthTime Time when the End-User authentication occurred
	AuthTime time.Time

	issuer  string
	authReq *sessAuthRequest
	now     func() time.Time
}

// PrefillIDToken can be used to create a basic ID token containing all required
// claims, mapped with information from this request. The issuer and subject
// will be set as provided, and the token's expiry will be set to the
// appropriate time base on the validity period
//
// Aside from the explicitly passed fields, the following information will be set:
// * Audience (aud) will contain the Client ID
// * ACR claim set
// * AMR claim set
// * Issued At (iat) time set
// * Auth Time (auth_time) time set
// * Nonce that was originally passed in, if there was one
func (t *TokenRequest) PrefillIDToken(sub string, expires time.Time) oidc.IDClaims {
	// TODO
	// Extra:    map[string]interface{}{},
	return oidc.IDClaims{
		Issuer:   t.issuer,
		Subject:  sub,
		Expiry:   oidc.UnixTime(expires.Unix()),
		Audience: oidc.StrOrSlice{t.ClientID},
		ACR:      t.Authorization.ACR,
		AMR:      t.Authorization.AMR,
		IssuedAt: oidc.UnixTime(t.now().Unix()),
		AuthTime: oidc.UnixTime(t.AuthTime.Unix()),
		Nonce:    t.Nonce,
	}
}

// PrefillAccessToken can be used to create a basic access token containing all
// required claims, mapped with information from this request. The issuer and
// subject will be set as provided, and the token's expiry will be set to the
// appropriate time base on the validity period
//
// Aside from the explicitly passed fields, the following information will be set:
// * Audience (aud) will contain the Client ID
// * ACR claim set
// * AMR claim set
// * Issued At (iat) time set
// * Auth Time (auth_time) time set
// * Scope from the Authorization
// * Randomly generated JWTID (uuid v4)
// * Client ID for this request
func (t *TokenRequest) PrefillAccessToken(sub string, expires time.Time) oidc.AccessTokenClaims {
	// TODO -
	// LoginSessionID: t.SessionID,
	// Extra:          map[string]interface{}{},
	return oidc.AccessTokenClaims{
		Issuer:   t.issuer,
		Subject:  sub,
		Expiry:   oidc.UnixTime(expires.Unix()),
		Audience: oidc.StrOrSlice{t.ClientID},
		ACR:      t.Authorization.ACR,
		AMR:      t.Authorization.AMR,
		IssuedAt: oidc.UnixTime(t.now().Unix()),
		AuthTime: oidc.UnixTime(t.AuthTime.Unix()),
		Scope:    strings.Join(t.Authorization.Scopes, " "),
		JWTID:    internal.MustUUIDv4(),
		ClientID: t.ClientID,
	}
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// IssueRefreshToken indicates if we should issue a refresh token.
	IssueRefreshToken bool

	// AccessToken is returned as the access token for the request to this
	// endpoint. It is up to the application to store _all_ the desired
	// information in the token correctly, and to obey the OAuth2 JWT profile
	// spec (https://datatracker.ietf.org/doc/html/rfc9068). The handler will
	// make no changes to this token.
	AccessToken oidc.AccessTokenClaims

	// IDToken is returned as the id_token for the request to this endpoint. It
	// is up to the application to store _all_ the desired information in the
	// token correctly, and to obey the OIDC spec. The handler will make no
	// changes to this token.
	IDToken oidc.IDClaims

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, assuming one is issued.
	RefreshTokenValidUntil time.Time
}

type unauthorizedErr interface {
	error
	Unauthorized() bool
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
func (o *OIDC) Token(w http.ResponseWriter, req *http.Request, handler func(req *TokenRequest) (*TokenResponse, error)) error {
	treq, err := oauth2.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return err
	}

	resp, err := o.token(req.Context(), treq, handler)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return err
	}

	if err := oauth2.WriteTokenResponse(w, resp); err != nil {
		_ = oauth2.WriteError(w, req, err)
		return err
	}

	return nil
}

func (o *OIDC) token(ctx context.Context, req *oauth2.TokenRequest, handler func(req *TokenRequest) (*TokenResponse, error)) (*oauth2.TokenResponse, error) {
	var sess *sessionV2
	var err error

	var isRefresh bool

	switch req.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		sess, err = o.fetchCodeSession(ctx, req)
	case oauth2.GrantTypeRefreshToken:
		isRefresh = true
		sess, err = o.fetchRefreshSession(ctx, req)

	default:
		err = &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", req.GrantType)}
	}
	if err != nil {
		return nil, err
	}

	if o.now().After(sess.Expiry) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	// check to see if we're working with the same client
	if sess.ClientID != req.ClientID {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}

	// validate the client
	cok, err := o.clients.ValidateClientSecret(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check client id & secret", Cause: err}

	}
	if !cok {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "Invalid client secret"}
	}

	// PKCE only applies on the authorization code grant type
	if req.GrantType == oauth2.GrantTypeAuthorizationCode {
		// If the client is public and we require pkce, reject it if there's no
		// verifier.
		reqPKCE, err := o.clients.RequiresPKCE(req.ClientID)
		if err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check if client is public", Cause: err}
		}
		if reqPKCE && req.CodeVerifier == "" {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
		}

		// Verify the code verifier against the session data
		if req.CodeVerifier != "" {
			if !verifyCodeChallenge(req.CodeVerifier, sess.Request.CodeChallenge) {
				return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
			}
		}
	}

	// Call the handler with information about the request, and get the response.
	if sess.Authorization == nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "session authorization is nil"}
	}

	tr := &TokenRequest{
		SessionID: sess.ID,
		ClientID:  req.ClientID,
		Authorization: Authorization{
			Scopes: sess.Authorization.Scopes,
			ACR:    sess.Authorization.ACR,
			AMR:    sess.Authorization.AMR,
		},
		GrantType:          req.GrantType,
		SessionRefreshable: strsContains(sess.Authorization.Scopes, "offline_access"),
		IsRefresh:          isRefresh,
		Nonce:              sess.Request.Nonce,
		AuthTime:           sess.Authorization.AuthorizedAt,

		issuer:  o.issuer,
		authReq: sess.Request,
		now:     o.now,
	}

	tresp, err := handler(tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	if tresp.IDToken.Expiry == 0 {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "id token cannot have a 0 expiry"}
	}

	if tresp.IssueRefreshToken && tresp.RefreshTokenValidUntil.Before(o.now()) {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "refresh token must be valid > now"}
	}

	// If we're allowing refresh, issue one of those too.
	// do this after, as it'll set a longer expiration on the session
	var refreshTok string
	if tresp.IssueRefreshToken {
		urefreshtok, srefreshtok, err := newToken(sess.ID, tresp.RefreshTokenValidUntil)
		if err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to generate access token", Cause: err}
		}
		sess.Expiry = srefreshtok.Expiry
		sess.RefreshToken = srefreshtok
		sess.Stage = sessionStageRefreshable

		refreshTok, err = marshalToken(urefreshtok)
		if err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to marshal refresh token", Cause: err}
		}
	} else {
		// clear any token
		sess.RefreshToken = nil
	}

	// update the session stage before we put it, we will be issuing a token.
	sess.Stage = sessionStageAccessTokenIssued

	if err := putSession(ctx, o.smgr, sess); err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to put access token", Cause: err}
	}

	h, err := o.keysetHandle.Handle(ctx)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "getting handle", Cause: err}
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "creating signer from handle", Cause: err}
	}

	rawIDJWT, err := tresp.IDToken.ToJWT(nil)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "mapping id claims to jwt", Cause: err}
	}

	sidt, err := signer.SignAndEncode(rawIDJWT)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign id token", Cause: err}
	}

	rawATJWT, err := tresp.AccessToken.ToJWT(nil)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "mapping access claims to jwt", Cause: err}
	}

	sat, err := signer.SignAndEncode(rawATJWT)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign access token", Cause: err}
	}

	return &oauth2.TokenResponse{
		AccessToken:  sat,
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    tresp.AccessToken.Expiry.Time().Sub(o.now()),
		ExtraParams: map[string]interface{}{
			"id_token": string(sidt),
		},
	}, nil
}

// fetchCodeSession handles loading the session for a code grant.
func (o *OIDC) fetchCodeSession(ctx context.Context, treq *oauth2.TokenRequest) (*sessionV2, error) {
	ucode, err := unmarshalToken(treq.Code)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}

	sess, err := getSession(ctx, o.smgr, ucode.SessionId)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get session from storage", Cause: err}
	}
	if sess == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "sesion expired"}
	}

	if sess.AuthCodeRedeemed || o.now().After(sess.AuthCode.Expiry) {
		// Drop the session too, assume we're under some kind of replay.
		// https://tools.ietf.org/html/rfc6819#section-4.4.1.1
		if err := o.smgr.DeleteSession(ctx, sess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(ucode, sess.AuthCode)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid code", Cause: err}
	}
	if !ok {
		// if we're passed an invalid code, assume we're under attack and drop the session
		if err := o.smgr.DeleteSession(ctx, sess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code", Cause: err}
	}

	sess.AuthCodeRedeemed = true

	return sess, nil
}

// fetchCodeSession handles loading the session for a refresh grant.
func (o *OIDC) fetchRefreshSession(ctx context.Context, treq *oauth2.TokenRequest) (*sessionV2, error) {
	urefresh, err := unmarshalToken(treq.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}

	sess, err := getSession(ctx, o.smgr, urefresh.SessionId)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to get session from storage", Cause: err}
	}
	if sess == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired", Cause: err}
	}

	if sess.RefreshToken == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "no refresh token issued for session"}
	}

	if o.now().After(sess.Expiry) || o.now().After(sess.RefreshToken.Expiry) {
		if err := o.smgr.DeleteSession(ctx, sess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}

	ok, err := tokensMatch(urefresh, sess.RefreshToken)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "invalid refresh token", Cause: err}
	}
	if !ok {
		// if we're passed an invalid refresh token, assume we're under attack and drop the session
		if err := o.smgr.DeleteSession(ctx, sess.ID); err != nil {
			return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to delete session from storage", Cause: err}
		}
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token", Cause: err}
	}

	// Drop the current token, it's been redeemed. The caller can decide to
	// issue a new one.
	sess.RefreshToken = nil

	return sess, nil
}

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// appropriate response data in JSON format to the passed writer.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (o *OIDC) Userinfo(w http.ResponseWriter, req *http.Request, handler func(w io.Writer, uireq *UserinfoRequest) error) error {
	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &oauth2.BearerError{} // no content, just request auth
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	// TODO - replace this verification logic with oidc.Provider

	h, err := o.keysetHandle.Handle(req.Context())
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}
	ph, err := h.Public()
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	jwtVerifier, err := jwt.NewVerifier(ph)
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	jwtValidator, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:     &o.issuer,
		IgnoreAudiences:    true, // we don't care about the audience here, this is just introspecting the user
		ExpectedTypeHeader: ptrOrNil("at+jwt"),
	})
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	jwt, err := jwtVerifier.VerifyAndDecode(authSp[1], jwtValidator)
	if err != nil {
		be := &oauth2.BearerError{Code: oauth2.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	sub, err := jwt.Subject()
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		Subject: sub,
	}

	w.Header().Set("Content-Type", "application/json")

	if err := handler(w, uireq); err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = oauth2.WriteError(w, req, herr)
		return herr
	}

	return nil
}

func strsContains(strs []string, s string) bool {
	for _, str := range strs {
		if str == s {
			return true
		}
	}
	return false
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
