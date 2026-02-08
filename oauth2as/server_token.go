package oauth2as

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
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/internal/th"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
	"lds.li/oauth2ext/oauth2as/internal/token"
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
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// If zero, default expiry times will be used
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

	treq, err := oauth2.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}

	var resp *oauth2.TokenResponse
	switch treq.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		resp, err = s.codeToken(req.Context(), req, treq)
	case oauth2.GrantTypeRefreshToken:
		resp, err = s.refreshToken(req.Context(), req, treq)
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

func (s *Server) codeToken(ctx context.Context, req *http.Request, treq *oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	if treq.Code == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "code is required"}
	}

	// Verify DPoP proof if present. In the code flow, we allow any thumbprint -
	// the result is what we'll bind the grant to.
	dpopThumbprint, err := s.verifyDPoPProof(s.config.Issuer, req, nil)
	if err != nil {
		return nil, err
	}

	loadedGrant, err := s.getGrantFromAuthCode(ctx, treq.Code)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		}
		return nil, fmt.Errorf("failed to get grant by auth code: %w", err)
	}

	pt, _ := token.ParseUserToken(treq.Code, tokenUsageAuthCode) // already parsed in getGrantFromAuthCode, so this is safe
	if err := s.config.Storage.ExpireAuthCode(ctx, pt.ID()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		}
		return nil, fmt.Errorf("failed to expire auth code: %w", err)
	}

	if loadedGrant.grant.Request == nil {

		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid grant"}
	}

	// Validate that the redirect_uri matches the one from the authorization request
	if treq.RedirectURI != loadedGrant.grant.Request.RedirectURI {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "redirect URI mismatch"}
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
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	var alg *string
	if copts.signingAlg != "" {
		alg = &copts.signingAlg
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, loadedGrant.grant.Request.CodeChallenge) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// Update the grant with DPoP thumbprint if present
	if dpopThumbprint != "" {
		loadedGrant.additionalState.DPoPThumbprint = &dpopThumbprint
	}

	// TODO: Update grant expiry when DPoP binding is added
	if err := s.config.Storage.UpdateGrant(ctx, loadedGrant.grantID, loadedGrant.grant); err != nil {
		if errors.Is(err, ErrConcurrentUpdate) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
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
	}

	// TODO: Make TokenHandler callback optional for code exchange
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr) && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	trresp, _, err := s.buildTokenResponse(ctx, alg, loadedGrant, tresp, isDPoPBound)
	if err != nil && errors.Is(err, ErrConcurrentUpdate) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
	}
	return trresp, err
}

func (s *Server) refreshToken(ctx context.Context, req *http.Request, treq *oauth2.TokenRequest) (_ *oauth2.TokenResponse, retErr error) {
	if treq.RefreshToken == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "refresh token is required"}
	}

	loadedGrant, err := s.getGrantFromRefreshToken(ctx, treq.RefreshToken)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
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
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		}
		// Token is expired but not replaced. Just a normal expiration.
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
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
					return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
				}
				return nil, fmt.Errorf("failed to update refresh token with grace expiry: %w", err)
			}
		} else {
			if err := s.config.Storage.ExpireRefreshToken(ctx, pt.ID()); err != nil {
				if errors.Is(err, ErrNotFound) {
					return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
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

	if storedThumbprint != "" {
		thumbprint, err := s.verifyDPoPProof(s.config.Issuer, req, &storedThumbprint)
		if err != nil {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "DPoP proof key mismatch"}
		}
		if thumbprint == "" {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "DPoP proof required"}
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

	var alg *string
	if copts.signingAlg != "" {
		alg = &copts.signingAlg
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
	}
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr) && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	trresp, newRTID, err := s.buildTokenResponse(ctx, alg, loadedGrant, tresp, isDPoPBound)
	if errors.Is(err, ErrConcurrentUpdate) {
		// expire the grant, there's likely another issuance in flight.
		if err := s.config.Storage.ExpireGrant(ctx, loadedGrant.grantID); err != nil {
			slog.WarnContext(ctx, "failed to expire grant", "error", err)
		}
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
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
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "concurrent update detected"}
		} else if err != nil {
			return nil, fmt.Errorf("failed to update old refresh token: %w", err)
		}
	}

	return trresp, nil
}

// buildTokenResponse creates the oauth token response for code and refresh.
// It works with both auth code grants and refresh token grants via the grantLoader interface.
func (s *Server) buildTokenResponse(ctx context.Context, alg *string, loadedGrant grantLoader, tresp *TokenResponse, isDPoPBound bool) (_ *oauth2.TokenResponse, refreshTokenID string, _ error) {
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

	var (
		idSigned string
		atSigned string
	)
	if alg != nil {
		algSigner, ok := s.config.Signer.(AlgorithmSigner)
		if !ok {
			return nil, "", fmt.Errorf("explicit algorithm requested, but signer does not implement AlgorithmSigner")
		}
		idSigned, err = algSigner.SignAndEncodeForAlgorithm(*alg, idc)
		if err != nil {
			return nil, "", fmt.Errorf("signing id token with algorithm %s: %w", *alg, err)
		}
		atSigned, err = algSigner.SignAndEncodeForAlgorithm(*alg, ac)
		if err != nil {
			return nil, "", fmt.Errorf("signing access token with algorithm %s: %w", *alg, err)
		}
	} else {
		idSigned, err = s.config.Signer.SignAndEncode(idc)
		if err != nil {
			return nil, "", fmt.Errorf("signing id token: %w", err)
		}
		atSigned, err = s.config.Signer.SignAndEncode(ac)
		if err != nil {
			return nil, "", fmt.Errorf("signing access token: %w", err)
		}
	}

	tokenType := "bearer"
	if isDPoPBound {
		tokenType = "DPoP"
	}

	return &oauth2.TokenResponse{
		AccessToken:  atSigned,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresIn:    acExp.Sub(s.now()),
		ExtraParams: map[string]any{
			"id_token": string(idSigned),
		},
	}, rtID, nil
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
	rjwtopts.IssuedAt = th.Ptr(s.now())
	rjwtopts.ExpiresAt = th.Ptr(idExp)
	rjwtopts.CustomClaims["auth_time"] = grant.GrantedAt.Unix()

	// defaulted values
	if rjwtopts.Subject == nil {
		rjwtopts.Subject = &grant.UserID
	}
	if rjwtopts.Audience == nil && len(rjwtopts.Audiences) == 0 {
		rjwtopts.Audience = &grant.ClientID
	}

	// TODO: Add nonce claim to ID token if provided in authorization request
	// rjwtopts.CustomClaims["nonce"] = grant.Request.Nonce

	rjwt, err := jwt.NewRawJWT(rjwtopts)
	if err != nil {
		return nil, fmt.Errorf("creating raw jwt: %w", err)
	}

	return rjwt, nil
}

func (s *Server) buildAccessTokenClaims(grantID string, grant *StoredGrant, tresp *TokenResponse) (_ *jwt.RawJWT, expiresAt time.Time, _ error) {
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
	rjwtopts.TypeHeader = th.Ptr("at+jwt")

	rjwtopts.Issuer = &s.config.Issuer
	rjwtopts.IssuedAt = th.Ptr(s.now())
	rjwtopts.ExpiresAt = th.Ptr(atExp)
	rjwtopts.JWTID = th.Ptr(newUUIDv4())
	rjwtopts.CustomClaims["client_id"] = grant.ClientID
	rjwtopts.CustomClaims[claimGrantID] = grantID

	var addState storedAdditionalState
	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &addState); err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}
	if addState.DPoPThumbprint != nil {
		rjwtopts.CustomClaims["jkt"] = *addState.DPoPThumbprint
	}

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

// verifyDPoPProof extracts and verifies the DPoP header from a request. Returns
// the thumbprint if a valid DPoP proof is provided, empty string if no DPoP
// header is present, or an error if the proof is invalid. The
// expectedThumbprint parameter is optional, if it is not nil, the thumbprint
// will be validated against it.
func (s *Server) verifyDPoPProof(iss string, req *http.Request, expectedThumbprint *string) (thumbprint string, err error) {
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader == "" {
		if expectedThumbprint != nil {
			return "", fmt.Errorf("DPoP header required")
		}
		return "", nil
	}

	if s.config.DPoPVerifier == nil {
		slog.DebugContext(req.Context(), "DPoP proof provided but DPoP is not supported")
		return "", nil
	}

	issURL, err := url.Parse(iss)
	if err != nil {
		return "", fmt.Errorf("failed to parse issuer: %w", err)
	}

	opts := &dpop.ValidatorOpts{
		ExpectedHTM:      th.Ptr(req.Method),
		ExpectedHTU:      th.Ptr(fmt.Sprintf("%s://%s%s", issURL.Scheme, issURL.Host, req.URL.Path)),
		AllowUnsetHTMHTU: true, // Allow requests without HTM/HTU if the client doesn't require them
	}
	if expectedThumbprint == nil {
		opts.IgnoreThumbprint = true
	} else {
		opts.ExpectedThumbprint = *expectedThumbprint
	}

	// Verify the DPoP proof (verifier will validate HTM/HTU from request)
	validator, err := dpop.NewValidator(opts)
	if err != nil {
		return "", fmt.Errorf("failed to create validator: %w", err)
	}
	res, err := s.config.DPoPVerifier.VerifyAndDecode(dpopHeader, validator)
	if err != nil {
		return "", fmt.Errorf("failed to verify DPoP proof: %w", err)
	}

	return res.Thumbprint, nil
}
