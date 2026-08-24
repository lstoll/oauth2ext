package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as/internal/token"
	"lds.li/oauth2ext/oauth2as/oauth2proto"
	"lds.li/oauth2ext/oidc"
)

const (
	claimGrantID = "grid"
)

var (
	tokenUsageAuthCode = token.Usage{Name: "auth_code", Prefix: "c"}
	tokenUsageRefresh  = token.Usage{Name: "refresh_token", Prefix: "r"}
)

type TokenHandler func(_ context.Context, req *TokenRequest) (*TokenResponse, error)

// IDTokenClaims contains application-selected identity claims. The server
// constructs the token envelope and binding claims.
type IDTokenClaims struct {
	Subject    string
	ACR        string
	AMR        []string
	Additional map[string]any
}

// AccessTokenClaims contains application-selected authorization claims. The
// server constructs the token envelope and binding claims.
type AccessTokenClaims struct {
	Subject    string
	Audiences  []string
	Scopes     []string
	Additional map[string]any
}

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// GrantID is the ID of the grant that was used to obtain the token.
	GrantID string
	// UserID is the user ID that was granted access.
	UserID string
	// ClientID is the client ID that was used to obtain the token.
	ClientID string
	// GrantedScopes are the scopes that were granted.
	GrantedScopes []string
	// Metadata is the metadata that was associated with the grant.
	Metadata []byte
	// DecryptedMetadata is the decrypted metadata that was associated with the
	// grant.
	DecryptedMetadata []byte

	// IsRefresh indicates if this is a refresh token request.
	IsRefresh bool

	// DPoPBound indicates whether this grant is bound to a DPoP key. If true,
	// all token requests for this grant must include a valid DPoP proof.
	DPoPBound bool
	// DPoPProof includes the verified DPoP proof, if present.
	DPoPProof *dpop.Proof
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// If zero, the configured default validity is used.
	IDTokenExpiry     time.Time
	AccessTokenExpiry time.Time

	// IDTokenClaims contains application-selected claims. Additional is for
	// custom claims and must not contain a server-managed or typed claim name.
	IDTokenClaims *IDTokenClaims
	// AccessTokenClaims contains application-selected claims. Additional is for
	// custom claims and must not contain a server-managed or typed claim name.
	AccessTokenClaims *AccessTokenClaims

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, if one is issued. If zero, the default will be used.
	RefreshTokenValidUntil time.Time

	// Metadata is the metadata that was associated with the grant. If nil, the
	// existing metadata will be re-used.
	Metadata []byte
	// EncryptedMetadata is the encrypted metadata that was associated with the
	// grant. If nil, the existing encrypted metadata will be re-used.
	EncryptedMetadata []byte
}

// TokenHandler is used to handle the access token endpoint for code flow
// requests. This can handle both the initial access token request, as well as
// subsequent calls for refreshes.
//
// If a handler returns an error, it will be checked and the endpoint will
// respond to the user appropriately. The session will not be invalidated
// automatically, it it the responsibility of the handler to delete if it
// requires this. * If the error implements an `Unauthorized() bool` method and
// the result of calling this is true, the caller will be notified of an
// `invalid_grant`. The error text will be returned as the `error_description` *
// All other errors will result an an InternalServerError
//
// This will always return a response to the user, regardless of success or
// failure. As such, once returned the called can assume the HTTP request has
// been dealt with appropriately
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (s *Server) TokenHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	treq, err := oauth2proto.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2proto.WriteError(w, req, err)
		return
	}

	var resp *oauth2proto.TokenResponse
	switch treq.GrantType {
	case oauth2proto.GrantTypeAuthorizationCode:
		resp, err = s.codeToken(req.Context(), req, treq)
	case oauth2proto.GrantTypeRefreshToken:
		resp, err = s.refreshToken(req.Context(), req, treq)
	default:
		err = &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", treq.GrantType)}
	}
	if err != nil {
		s.logger.WarnContext(req.Context(), "error in token handler", "grant-type", treq.GrantType, "err", err)
		_ = oauth2proto.WriteError(w, req, err)
		return
	}

	if err := oauth2proto.WriteTokenResponse(w, resp); err != nil {
		s.logger.ErrorContext(req.Context(), "error writing token response", "grant-type", treq.GrantType, "err", err)
		_ = oauth2proto.WriteError(w, req, err)
		return
	}
}

func (s *Server) codeToken(ctx context.Context, req *http.Request, treq *oauth2proto.TokenRequest) (*oauth2proto.TokenResponse, error) {
	if treq.Code == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "code is required"}
	}

	// Verify DPoP proof if present. In the code flow, we allow any thumbprint -
	// the result is what we'll bind the grant to.
	dpopProof, err := s.verifyDPoPProof(s.config.Issuer, req, nil)
	if err != nil {
		return nil, err
	}
	var dpopThumbprint string
	if dpopProof != nil {
		dpopThumbprint = dpopProof.Thumbprint
	}

	loadedGrant, err := s.getGrantFromAuthCode(ctx, treq.Code)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		}
		return nil, fmt.Errorf("failed to get grant by auth code: %w", err)
	}

	pt, _ := token.ParseUserToken(treq.Code, tokenUsageAuthCode) // already parsed in getGrantFromAuthCode, so this is safe
	if err := s.config.Storage.ExpireAuthCode(ctx, pt.ID()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		}
		return nil, fmt.Errorf("failed to expire auth code: %w", err)
	}

	if loadedGrant.grant.Request == nil {

		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid grant"}
	}

	// Validate that the redirect_uri matches the one from the authorization request
	if treq.RedirectURI != loadedGrant.grant.Request.RedirectURI {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "redirect URI mismatch"}
	}

	if err := s.validateTokenClient(ctx, treq, loadedGrant.grant.ClientID); err != nil {
		return nil, err
	}

	optsForClient, err := s.config.Clients.ClientOpts(ctx, loadedGrant.grant.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client opts: %w", err)
	}
	copts := &clientOpts{}
	for _, opt := range optsForClient {
		opt(copts)
	}

	// Reject if PKCE is required but no code verifier was provided
	if !copts.skipPKCE && treq.CodeVerifier == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	idTokenAlgorithm := s.defaultIDTokenSigningAlgorithm()
	if copts.idTokenSigningAlgorithm != "" {
		idTokenAlgorithm = copts.idTokenSigningAlgorithm
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, loadedGrant.grant.Request.CodeChallenge) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// Update the grant with DPoP thumbprint if present
	if dpopThumbprint != "" {
		loadedGrant.additionalState.DPoPThumbprint = &dpopThumbprint
	}

	// TODO: Update grant expiry when DPoP binding is added
	if err := s.config.Storage.UpdateGrant(ctx, loadedGrant.grantID, loadedGrant.grant); err != nil {
		if errors.Is(err, ErrConcurrentUpdate) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
		}
		return nil, fmt.Errorf("failed to update grant: %w", err)
	}

	// Check if this grant is DPoP-bound by looking for thumbprint in metadata
	var isDPoPBound bool
	if loadedGrant.additionalState.DPoPThumbprint != nil && *loadedGrant.additionalState.DPoPThumbprint != "" {
		isDPoPBound = true
	}

	tr := &TokenRequest{
		GrantID:           loadedGrant.grantID,
		UserID:            loadedGrant.grant.UserID,
		ClientID:          loadedGrant.grant.ClientID,
		GrantedScopes:     loadedGrant.grant.GrantedScopes,
		Metadata:          loadedGrant.grant.Metadata,
		DecryptedMetadata: loadedGrant.decryptedMetadata,
		IsRefresh:         false,
		DPoPBound:         isDPoPBound,
		DPoPProof:         dpopProof,
	}

	// TODO: Make TokenHandler callback optional for code exchange
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr) && uaerr.Unauthorized() {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	trresp, _, err := s.buildTokenResponse(ctx, idTokenAlgorithm, loadedGrant, tresp, isDPoPBound)
	if err != nil && errors.Is(err, ErrConcurrentUpdate) {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
	}
	return trresp, err
}

func (s *Server) refreshToken(ctx context.Context, req *http.Request, treq *oauth2proto.TokenRequest) (_ *oauth2proto.TokenResponse, retErr error) {
	if treq.RefreshToken == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "refresh token is required"}
	}

	loadedGrant, err := s.getGrantFromRefreshToken(ctx, treq.RefreshToken)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		}
		return nil, fmt.Errorf("failed to get grant by refresh token: %w", err)
	}

	pt, _ := token.ParseUserToken(treq.RefreshToken, tokenUsageRefresh)

	// Check if token is valid for use
	if s.now().After(loadedGrant.refreshToken.ValidUntil) {
		if loadedGrant.refreshToken.ReplacedByTokenID != "" {
			// Token is expired AND replaced. This means it was used, rotated,
			// and the grace period has passed. This is a likely replay/theft.
			if err := s.config.Storage.ExpireGrant(ctx, loadedGrant.grantID); err != nil {
				return nil, fmt.Errorf("failed to revoke grant on refresh token reuse: %w", err)
			}
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		}
		// Token is expired but not replaced. Just a normal expiration.
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// Handle grace period for rotated tokens
	if loadedGrant.refreshToken.ReplacedByTokenID != "" {
		// Strict Option 2: Revoke the new one, and issue a third.
		// Token reused within grace period: revoke the replacement token and issue a new one
		if err := s.config.Storage.ExpireRefreshToken(ctx, loadedGrant.refreshToken.ReplacedByTokenID); err != nil {
			if !errors.Is(err, ErrNotFound) {
				return nil, fmt.Errorf("failed to revoke replaced token during reuse: %w", err)
			}
		}
	} else {
		if s.config.RefreshTokenRotationGracePeriod > 0 {
			loadedGrant.refreshToken.ValidUntil = s.now().Add(s.config.RefreshTokenRotationGracePeriod)
			if err := s.config.Storage.UpdateRefreshToken(ctx, pt.ID(), loadedGrant.refreshToken); err != nil {
				if errors.Is(err, ErrConcurrentUpdate) {
					return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
				}
				return nil, fmt.Errorf("failed to update refresh token with grace expiry: %w", err)
			}
		} else {
			if err := s.config.Storage.ExpireRefreshToken(ctx, pt.ID()); err != nil {
				if errors.Is(err, ErrNotFound) {
					return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
				}
				return nil, fmt.Errorf("failed to expire refresh token: %w", err)
			}
		}
	}

	// Enforce DPoP binding if the grant was initiated with DPoP
	var storedThumbprint string
	if loadedGrant.additionalState.DPoPThumbprint != nil {
		storedThumbprint = *loadedGrant.additionalState.DPoPThumbprint
	}

	var dpopProof *dpop.Proof
	if storedThumbprint != "" {
		var err error
		dpopProof, err = s.verifyDPoPProof(s.config.Issuer, req, &storedThumbprint)
		if err != nil {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "DPoP proof key mismatch"}
		}
		if dpopProof == nil || dpopProof.Thumbprint == "" {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "DPoP proof required"}
		}
	}

	optsForClient, err := s.config.Clients.ClientOpts(ctx, loadedGrant.grant.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client opts: %w", err)
	}
	copts := &clientOpts{}
	for _, opt := range optsForClient {
		opt(copts)
	}

	idTokenAlgorithm := s.defaultIDTokenSigningAlgorithm()
	if copts.idTokenSigningAlgorithm != "" {
		idTokenAlgorithm = copts.idTokenSigningAlgorithm
	}

	// Check if this grant is DPoP-bound by looking for thumbprint in metadata
	isDPoPBound := storedThumbprint != ""

	tr := &TokenRequest{
		GrantID:           loadedGrant.grantID,
		UserID:            loadedGrant.grant.UserID,
		ClientID:          loadedGrant.grant.ClientID,
		GrantedScopes:     loadedGrant.grant.GrantedScopes,
		Metadata:          loadedGrant.grant.Metadata,
		DecryptedMetadata: loadedGrant.decryptedMetadata,
		IsRefresh:         true,
		DPoPBound:         isDPoPBound,
		DPoPProof:         dpopProof,
	}
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr) && uaerr.Unauthorized() {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	trresp, newRTID, err := s.buildTokenResponse(ctx, idTokenAlgorithm, loadedGrant, tresp, isDPoPBound)
	if errors.Is(err, ErrConcurrentUpdate) {
		// expire the grant, there's likely another issuance in flight.
		if err := s.config.Storage.ExpireGrant(ctx, loadedGrant.grantID); err != nil {
			slog.WarnContext(ctx, "failed to expire grant", "error", err)
		}
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
	} else if err != nil {
		return nil, fmt.Errorf("failed to build refresh token response: %w", err)
	}

	// If we are rotating with grace, update the old token to point to the new one
	if s.config.RefreshTokenRotationGracePeriod > 0 && newRTID != "" {
		pt, _ := token.ParseUserToken(treq.RefreshToken, tokenUsageRefresh)
		loadedGrant.refreshToken.ReplacedByTokenID = newRTID
		err := s.config.Storage.UpdateRefreshToken(ctx, pt.ID(), loadedGrant.refreshToken)
		if errors.Is(err, ErrConcurrentUpdate) {
			// if we get here, hard fail the token regardless of grace period -
			// we've had a duplicate update, and risk forking the token history.
			// This is an edge enough case that it's not worth trying to
			// recover.
			if err := s.config.Storage.ExpireGrant(ctx, loadedGrant.grantID); err != nil {
				slog.WarnContext(ctx, "failed to expire grant", "error", err)
			}
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
		} else if err != nil {
			return nil, fmt.Errorf("failed to update old refresh token: %w", err)
		}
	}

	return trresp, nil
}

// buildTokenResponse creates the oauth token response for code and refresh.
// It works with both auth code grants and refresh token grants via the grantLoader interface.
func (s *Server) buildTokenResponse(ctx context.Context, idTokenAlgorithm jwt.Algorithm, loadedGrant grantLoader, tresp *TokenResponse, isDPoPBound bool) (_ *oauth2proto.TokenResponse, refreshTokenID string, _ error) {
	// Update metadata from the handler response
	if tresp.Metadata != nil {
		loadedGrant.Grant().Metadata = tresp.Metadata
	}
	if tresp.EncryptedMetadata != nil {
		loadedGrant.SetDecryptedMetadata(tresp.EncryptedMetadata)
	}

	var refreshToken string
	var rtID string
	if slices.Contains(loadedGrant.Grant().GrantedScopes, oidc.ScopeOfflineAccess) {
		rtUntil := tresp.RefreshTokenValidUntil
		if rtUntil.IsZero() {
			rtUntil = s.now().Add(s.config.RefreshTokenValidity)
		}

		// Cap the refresh token expiry at the grant's absolute expiration
		if rtUntil.After(loadedGrant.Grant().ExpiresAt) {
			rtUntil = loadedGrant.Grant().ExpiresAt
		}

		var err error
		// Build a refresh token grant for creating the refresh token
		rtGrant := &loadedRefreshTokenGrant{
			grant:             loadedGrant.Grant(),
			grantID:           loadedGrant.GrantID(),
			decryptedMetadata: loadedGrant.DecryptedMetadata(),
			additionalState:   *loadedGrant.AdditionalState(),
		}
		_, refreshToken, rtID, err = s.putGrantWithRefreshToken(ctx, rtGrant, rtUntil)
		if err != nil {
			return nil, "", fmt.Errorf("error putting grant with refresh token: %v", err)
		}
	} else {
		// Update grant metadata even when no refresh token is issued
		// TODO: Verify if metadata updates without refresh tokens are necessary
		if err := s.config.Storage.UpdateGrant(ctx, loadedGrant.GrantID(), loadedGrant.Grant()); err != nil {
			return nil, "", fmt.Errorf("error updating grant: %v", err)
		}
	}

	// TODO: Conditionally issue ID tokens only when openid scope is granted

	idc, err := s.buildIDClaims(loadedGrant.Grant(), tresp)
	if err != nil {
		return nil, "", fmt.Errorf("building id token claims: %w", err)
	}
	ac, acExp, err := s.buildAccessTokenClaims(loadedGrant.GrantID(), loadedGrant.Grant(), tresp)
	if err != nil {
		return nil, "", fmt.Errorf("building access token claims: %w", err)
	}

	accessTokenAlgorithm := s.accessTokenSigningAlgorithm()
	atSigned, err := s.config.Signer.SignJWT(ctx, accessTokenAlgorithm, ac)
	if err != nil {
		return nil, "", fmt.Errorf("signing access token with algorithm %s: %w", accessTokenAlgorithm, err)
	}
	idSigned, err := s.config.Signer.SignJWT(ctx, idTokenAlgorithm, idc)
	if err != nil {
		return nil, "", fmt.Errorf("signing ID token with algorithm %s: %w", idTokenAlgorithm, err)
	}

	tokenType := "bearer"
	if isDPoPBound {
		tokenType = "DPoP"
	}

	return &oauth2proto.TokenResponse{
		AccessToken:  atSigned,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresIn:    acExp.Sub(s.now()),
		ExtraParams: map[string]any{
			"id_token": idSigned,
		},
	}, rtID, nil
}

func (s *Server) buildIDClaims(grant *StoredGrant, tresp *TokenResponse) (JWTSigningInput, error) {
	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = s.now().Add(s.config.IDTokenValidity)
	}
	application := tresp.IDTokenClaims
	claims, err := additionalClaims(nil, idTokenReservedClaims)
	if application != nil {
		claims, err = additionalClaims(application.Additional, idTokenReservedClaims)
	}
	if err != nil {
		return JWTSigningInput{}, err
	}
	subject := grant.UserID
	if application != nil && application.Subject != "" {
		subject = application.Subject
	}
	claims["iss"] = s.config.Issuer
	claims["sub"] = subject
	claims["aud"] = grant.ClientID
	claims["iat"] = s.now().Unix()
	claims["exp"] = idExp.Unix()
	claims["auth_time"] = grant.GrantedAt.Unix()
	if grant.Request != nil && grant.Request.Nonce != "" {
		claims["nonce"] = grant.Request.Nonce
	}
	if application != nil && application.ACR != "" {
		claims["acr"] = application.ACR
	}
	if application != nil && len(application.AMR) > 0 {
		claims["amr"] = slices.Clone(application.AMR)
	}
	return marshalSigningInput("", claims)
}

func (s *Server) buildAccessTokenClaims(grantID string, grant *StoredGrant, tresp *TokenResponse) (_ JWTSigningInput, expiresAt time.Time, _ error) {
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = s.now().Add(s.config.AccessTokenValidity)
	}
	application := tresp.AccessTokenClaims
	claims, err := additionalClaims(nil, accessTokenReservedClaims)
	if application != nil {
		claims, err = additionalClaims(application.Additional, accessTokenReservedClaims)
	}
	if err != nil {
		return JWTSigningInput{}, time.Time{}, err
	}
	subject := grant.UserID
	if application != nil && application.Subject != "" {
		subject = application.Subject
	}
	audiences := []string{grant.ClientID}
	if application != nil && len(application.Audiences) > 0 {
		audiences = slices.Clone(application.Audiences)
	}
	scopes := slices.Clone(grant.GrantedScopes)
	if application != nil && len(application.Scopes) > 0 {
		scopes = slices.Clone(application.Scopes)
	}
	claims["iss"] = s.config.Issuer
	claims["sub"] = subject
	claims["aud"] = audiences
	claims["iat"] = s.now().Unix()
	claims["exp"] = atExp.Unix()
	claims["jti"] = newUUIDv4()
	claims["client_id"] = grant.ClientID
	claims["scope"] = strings.Join(scopes, " ")
	claims[claimGrantID] = grantID

	var addState storedAdditionalState
	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &addState); err != nil {
			return JWTSigningInput{}, time.Time{}, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}
	if addState.DPoPThumbprint != nil {
		claims["cnf"] = map[string]any{"jkt": *addState.DPoPThumbprint}
	}
	input, err := marshalSigningInput("at+jwt", claims)
	if err != nil {
		return JWTSigningInput{}, time.Time{}, err
	}
	return input, atExp, nil
}

var idTokenReservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"auth_time": {}, "nonce": {}, "azp": {}, "acr": {}, "amr": {}, "at_hash": {}, "c_hash": {},
}

var accessTokenReservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"client_id": {}, "scope": {}, "cnf": {}, claimGrantID: {},
}

func additionalClaims(additional map[string]any, reserved map[string]struct{}) (map[string]any, error) {
	claims := make(map[string]any, len(additional)+12)
	for name, value := range additional {
		if _, isReserved := reserved[name]; isReserved {
			return nil, fmt.Errorf("claim %q is managed by the authorization server", name)
		}
		claims[name] = value
	}
	return claims, nil
}

func marshalSigningInput(typ string, claims map[string]any) (JWTSigningInput, error) {
	payload, err := jsonv2.Marshal(claims)
	if err != nil {
		return JWTSigningInput{}, fmt.Errorf("marshaling JWT claims: %w", err)
	}
	return JWTSigningInput{Type: typ, Payload: payload}, nil
}

func verifyCodeChallenge(codeVerifier, storedCodeChallenge string) bool {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashedVerifier := h.Sum(nil)
	computedChallenge := base64.RawURLEncoding.EncodeToString(hashedVerifier)
	return computedChallenge == storedCodeChallenge
}

// verifyDPoPProof extracts and verifies the DPoP header from a request. Returns
// a verified [dpop.Proof] if a valid DPoP proof is provided, nil if no DPoP
// header is present (and none is required), or an error if the proof is invalid.
// When expectedThumbprint is non-nil, the proof's thumbprint must match it.
func (s *Server) verifyDPoPProof(iss string, req *http.Request, expectedThumbprint *string) (proof *dpop.Proof, err error) {
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		if expectedThumbprint != nil {
			return nil, fmt.Errorf("DPoP header required")
		}
		return nil, nil
	}

	if s.config.DPoPVerifier == nil {
		slog.DebugContext(req.Context(), "DPoP proof provided but DPoP is not supported")
		return nil, nil
	}

	issURL, err := url.Parse(iss)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}

	opts := &dpop.ValidatorOpts{
		ExpectedHTM: new(req.Method),
		ExpectedHTU: new(fmt.Sprintf("%s://%s%s", issURL.Scheme, issURL.Host, req.URL.Path)),
	}
	if expectedThumbprint == nil {
		opts.IgnoreThumbprint = true
	} else {
		opts.ExpectedThumbprint = *expectedThumbprint
	}

	// Verify the DPoP proof (verifier will validate HTM/HTU from request)
	validator, err := dpop.NewValidator(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}
	res, err := s.config.DPoPVerifier.VerifyAndDecode(dpopHeader, validator)
	if err != nil {
		return nil, fmt.Errorf("failed to verify DPoP proof: %w", err)
	}

	return res, nil
}
