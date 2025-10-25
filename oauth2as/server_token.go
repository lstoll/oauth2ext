package oauth2as

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
	"lds.li/oauth2ext/oauth2as/internal/token"
	"lds.li/oauth2ext/oidc"
)

const (
	claimGrantID = "grid"

	tokenUsageAuthCode = "auth_code"
	tokenUsageRefresh  = "refresh_token"

	defaultSigningAlg = "ES256"
)

type TokenHandler func(_ context.Context, req *TokenRequest) (*TokenResponse, error)

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// GrantID is the ID of the grant that was used to obtain the token.
	GrantID uuid.UUID
	// UserID is the user ID that was granted access.
	UserID string
	// ClientID is the client ID that was used to obtain the token.
	ClientID string
	// GrantedScopes are the scopes that were granted.
	GrantedScopes []string
	// Metadata is the metadata that was associated with the grant.
	Metadata map[string]string
	// EncryptedMetadata is the decrypted metadata that was associated with the
	// grant.
	EncryptedMetadata map[string]string

	// IsRefresh indicates if this is a refresh token request.
	IsRefresh bool
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	/* // OverrideRefreshTokenIssuance can be used to override issuing a refresh
	// token if the client requested it, if true.
	OverrideRefreshTokenIssuance bool

	// OverrideRefreshTokenExpiry can be used to override the expiration of the
	// refresh token. If not set, the default will be used.
	OverrideRefreshTokenExpiry time.Time */

	// may be zero, if so defaulted
	IDTokenExpiry     time.Time
	AccessTokenExpiry time.Time

	// IDClaims are the claims that will be included in the ID token. These will
	// be serialized to JSON, and then returned in the token. This is optional.
	// The following claims will always be overridden:
	// - iss
	// - iat
	// - auth_time
	// - nonce
	// The following claims will be defaulted if not set:
	// - sub
	// - exp
	// - aud
	IDClaims *jwt.RawJWTOptions
	// AccessTokenClaims is the claims that will be included in the access token.
	// The claims will be serialized to JSON, and then returned in the token.
	// The following claims will always be overridden:
	// - iss
	// - client_id
	// - iat
	// - jti
	// The following claims will be defaulted if not set:
	// - sub
	// - exp
	// - aud
	AccessTokenClaims *jwt.RawJWTOptions

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, if one is issued. If zero, the default will be used.
	RefreshTokenValidUntil time.Time

	// Metadata is the metadata that was associated with the grant. If nil, the
	// existing metadata will be re-used.
	Metadata map[string]string
	// EncryptedMetadata is the encrypted metadata that was associated with the
	// grant. If nil, the existing encrypted metadata will be re-used.
	EncryptedMetadata map[string]string
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

	treq, err := oauth2.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	var resp *oauth2.TokenResponse
	switch treq.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		// this is for the initial issuance. we exchange the code for a token.
		resp, err = s.codeToken(req.Context(), treq)
	case oauth2.GrantTypeRefreshToken:
		// this is for subsequent refreshes. we exchange the refresh token for a new token.
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
	if treq.Code == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "code is required"}
	}

	// Create token from user token to get the stored value
	authToken, err := token.FromUserToken(treq.Code, tokenUsageAuthCode)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	grant, err := s.config.Storage.GetGrantByAuthCode(ctx, authToken.Stored())
	if err != nil {
		return nil, fmt.Errorf("failed to get grant by auth code: %w", err)
	}
	if grant == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	// update to note the code was used.
	oldAuthCode := grant.AuthCode
	grant.AuthCode = nil
	// TODO - update the expiry to match the extended time.
	if err := s.config.Storage.UpdateGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("failed to update grant: %w", err)
	}

	// storage should do this, but double check
	if s.now().After(grant.ExpiresAt) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "code expired"}
	}
	if subtle.ConstantTimeCompare(oldAuthCode, authToken.Stored()) == 0 {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	// we have a validated code.
	if err := s.validateTokenClient(ctx, treq, grant.ClientID); err != nil {
		return nil, err
	}

	optsForClient, err := s.config.Clients.ClientOpts(ctx, grant.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client opts: %w", err)
	}
	copts := &clientOpts{}
	for _, opt := range optsForClient {
		opt(copts)
	}

	// If the client is public and we require pkce, reject it if there's no
	// verifier.
	if !copts.skipPKCE && treq.CodeVerifier == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	alg := defaultSigningAlg
	if copts.signingAlg != "" {
		alg = copts.signingAlg
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, grant.Request.CodeChallenge) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// Unpack encrypted metadata if present
	var encryptedMetadata map[string]string
	if grant.EncryptedMetadata != nil {
		// Create token from the auth code to decrypt metadata
		authToken, err := token.FromUserToken(treq.Code, tokenUsageAuthCode)
		if err != nil {
			return nil, fmt.Errorf("failed to create token from auth code: %w", err)
		}

		decrypted, err := authToken.Decrypt(grant.EncryptedMetadata, grant.ID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
		}

		if err := json.Unmarshal(decrypted, &encryptedMetadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal decrypted metadata: %w", err)
		}
	}

	// we have a validated request. Call out to the handler to get the details.
	tr := &TokenRequest{
		GrantID:           grant.ID,
		UserID:            grant.UserID,
		ClientID:          grant.ClientID,
		GrantedScopes:     grant.GrantedScopes,
		Metadata:          grant.Metadata,
		EncryptedMetadata: encryptedMetadata,
		IsRefresh:         false,
	}

	// TODO - this should be optional
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return s.buildTokenResponse(ctx, alg, grant, tresp)
}

func (s *Server) refreshToken(ctx context.Context, treq *oauth2.TokenRequest) (_ *oauth2.TokenResponse, retErr error) {
	if treq.RefreshToken == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "refresh token is required"}
	}

	// Create token from user token to get the stored value
	refreshToken, err := token.FromUserToken(treq.RefreshToken, tokenUsageRefresh)
	if err != nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	grant, err := s.config.Storage.GetGrantByRefreshToken(ctx, refreshToken.Stored())
	if err != nil {
		return nil, fmt.Errorf("failed to get grant by auth code: %w", err)
	}
	if grant == nil {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// immediately create a new RT, and save it. We want to invalidate the old
	// one immediately.
	oldRefreshToken := grant.RefreshToken
	grant.RefreshToken = nil
	// TODO - expiry update here?

	if err := s.config.Storage.UpdateGrant(ctx, grant); err != nil {
		return nil, fmt.Errorf("failed to update grant: %w", err)
	}

	optsForClient, err := s.config.Clients.ClientOpts(ctx, grant.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client opts: %w", err)
	}
	copts := &clientOpts{}
	for _, opt := range optsForClient {
		opt(copts)
	}

	alg := defaultSigningAlg
	if copts.signingAlg != "" {
		alg = copts.signingAlg
	}

	// storage should do this, but double check.
	if s.now().After(grant.ExpiresAt) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}
	if subtle.ConstantTimeCompare(refreshToken.Stored(), oldRefreshToken) == 0 {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// Unpack encrypted metadata if present
	var encryptedMetadata map[string]string
	if grant.EncryptedMetadata != nil {
		// Create token from the old refresh token to decrypt metadata
		// We need to use the stored refresh token hash to reconstruct the token
		oldRefreshToken, err := token.FromUserToken(treq.RefreshToken, tokenUsageRefresh)
		if err != nil {
			return nil, fmt.Errorf("failed to create token from refresh token: %w", err)
		}

		decrypted, err := oldRefreshToken.Decrypt(grant.EncryptedMetadata, grant.ID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
		}

		if err := json.Unmarshal(decrypted, &encryptedMetadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal decrypted metadata: %w", err)
		}
	}

	// tresp, err := o.handler.RefreshToken(tr)
	// TODO - need to re-do this too.
	tr := &TokenRequest{
		GrantID:           grant.ID,
		UserID:            grant.UserID,
		ClientID:          grant.ClientID,
		GrantedScopes:     grant.GrantedScopes,
		Metadata:          grant.Metadata,
		EncryptedMetadata: encryptedMetadata,
		IsRefresh:         true,
	}
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return s.buildTokenResponse(ctx, alg, grant, tresp)
}

// buildTokenResponse creates the oauth token response for code and refresh.
// refreshSession can be nil, if it is and we should issue a refresh token, a
// new refresh session will be created.
func (s *Server) buildTokenResponse(ctx context.Context, alg string, grant *StoredGrant, tresp *TokenResponse) (_ *oauth2.TokenResponse, retErr error) {
	var (
		refreshTok string
		saveGrant  bool
	)
	defer func() {
		if saveGrant {
			if err := s.config.Storage.UpdateGrant(ctx, grant); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("error updating grant: %v", err))
			}
		}
	}()

	if slices.Contains(grant.GrantedScopes, oidc.ScopeOfflineAccess) {
		newToken := token.New(tokenUsageRefresh)
		refreshTok = newToken.User()
		grant.RefreshToken = newToken.Stored()
		saveGrant = true
	}

	// Update metadata if provided
	if tresp.Metadata != nil {
		grant.Metadata = tresp.Metadata
		saveGrant = true
	}

	// Update encrypted metadata if provided
	if tresp.EncryptedMetadata != nil {
		// Create a new token for encrypting the metadata
		// For refresh tokens, we need to use the new refresh token
		var encryptToken token.Token
		var err error
		if refreshTok != "" {
			// We have a new refresh token, use it to encrypt
			encryptToken, err = token.FromUserToken(refreshTok, tokenUsageRefresh)
			if err != nil {
				return nil, fmt.Errorf("failed to create token from refresh token: %w", err)
			}
		} else {
			// No refresh token, create a new one for encryption
			encryptToken = token.New(tokenUsageRefresh)
		}

		// Marshal the encrypted metadata
		emdjson, err := json.Marshal(tresp.EncryptedMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal encrypted metadata: %w", err)
		}

		// Encrypt the metadata
		encryptedMetadata, err := encryptToken.Encrypt(string(emdjson), grant.ID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}

		grant.EncryptedMetadata = encryptedMetadata
		saveGrant = true
	}

	// TODO - only try and issue an ID token if the openid scope was granted.

	idc, err := s.buildIDClaims(grant, tresp)
	if err != nil {
		return nil, fmt.Errorf("building id token claims: %w", err)
	}
	ac, acExp, err := s.buildAccessTokenClaims(grant, tresp)
	if err != nil {
		return nil, fmt.Errorf("building access token claims: %w", err)
	}

	signer, err := s.config.Signer.SignerForAlgorithm(ctx, alg)
	if err != nil {
		return nil, fmt.Errorf("getting signer for algorithm: %w", err)
	}

	idSigned, err := signer.SignAndEncode(idc)
	if err != nil {
		return nil, fmt.Errorf("signing id token: %w", err)
	}
	atSigned, err := signer.SignAndEncode(ac)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	return &oauth2.TokenResponse{
		AccessToken:  atSigned,
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    acExp.Sub(s.now()),
		ExtraParams: map[string]interface{}{
			"id_token": string(idSigned),
		},
	}, nil
}

func (s *Server) buildIDClaims(grant *StoredGrant, tresp *TokenResponse) (*jwt.RawJWT, error) {
	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = s.now().Add(s.config.IDTokenValidity)
	}

	rjwtopts := tresp.IDClaims

	if rjwtopts == nil {
		rjwtopts = &jwt.RawJWTOptions{}
	}
	if rjwtopts.CustomClaims == nil {
		rjwtopts.CustomClaims = make(map[string]any)
	}

	// fixed values
	rjwtopts.Issuer = &s.config.Issuer
	rjwtopts.Audience = &grant.ClientID
	rjwtopts.IssuedAt = ptr(s.now())
	rjwtopts.ExpiresAt = ptr(idExp)
	rjwtopts.CustomClaims["auth_time"] = grant.GrantedAt.Unix()

	// defaulted values
	if rjwtopts.Subject == nil {
		rjwtopts.Subject = &grant.UserID
	}
	if rjwtopts.Audience == nil && len(rjwtopts.Audiences) == 0 {
		rjwtopts.Audience = &grant.ClientID
	}

	// TODO nonce
	// rjwtopts.CustomClaims["nonce"] = grant.Request.Nonce

	rjwt, err := jwt.NewRawJWT(rjwtopts)
	if err != nil {
		return nil, fmt.Errorf("creating raw jwt: %w", err)
	}

	return rjwt, nil
}

func (s *Server) buildAccessTokenClaims(grant *StoredGrant, tresp *TokenResponse) (_ *jwt.RawJWT, expiresAt time.Time, _ error) {
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = s.now().Add(s.config.AccessTokenValidity)
	}

	rjwtopts := tresp.AccessTokenClaims

	if rjwtopts == nil {
		rjwtopts = &jwt.RawJWTOptions{}
	}
	if rjwtopts.CustomClaims == nil {
		rjwtopts.CustomClaims = make(map[string]any)
	}

	// fixed values
	rjwtopts.TypeHeader = ptr("at+jwt")

	rjwtopts.Issuer = &s.config.Issuer
	rjwtopts.IssuedAt = ptr(s.now())
	rjwtopts.ExpiresAt = ptr(atExp)
	rjwtopts.JWTID = ptr(uuid.New().String())
	rjwtopts.CustomClaims["client_id"] = grant.ClientID
	rjwtopts.CustomClaims[claimGrantID] = grant.ID.String()

	// defaulted values
	if rjwtopts.Subject == nil {
		rjwtopts.Subject = &grant.UserID
	}
	if rjwtopts.Audience == nil && len(rjwtopts.Audiences) == 0 {
		rjwtopts.Audience = &grant.ClientID
	}

	rjwt, err := jwt.NewRawJWT(rjwtopts)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("creating raw jwt: %w", err)
	}

	return rjwt, atExp, nil
}

func verifyCodeChallenge(codeVerifier, storedCodeChallenge string) bool {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashedVerifier := h.Sum(nil)
	computedChallenge := base64.RawURLEncoding.EncodeToString(hashedVerifier)
	return computedChallenge == storedCodeChallenge
}
