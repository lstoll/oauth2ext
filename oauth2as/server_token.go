package oauth2as

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as/internal/oauth2"
	"github.com/lstoll/oauth2ext/claims"
	"github.com/lstoll/oauth2ext/oidc"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

const (
	claimGrantID = "grid"
)

type TokenHandler func(_ context.Context, req *TokenRequest) (*TokenResponse, error)

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// Grant is the grant that was used to obtain the token.
	Grant *StoredGrant
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

	// IDClaims is the claims that will be included in the ID token. This is
	// optional. The following claims will always be overridden:
	// - sub
	// - iss
	// - aud
	// - exp
	// - iat
	// - auth_time
	// - nonce
	IDClaims *claims.RawIDClaims
	// AccessTokenClaims is the claims that will be included in the access token.
	// The following claims will always be overridden:
	// - sub
	// - iss
	// - aud
	// - exp
	// - iat
	// - jti
	// and the token header
	AccessTokenClaims *claims.RawAccessTokenClaims

	// OverrideIDSubject can be used to override the subject of the ID token.
	// If not set, the default will be used.
	OverrideIDSubject string
	// OverrideAccessTokenSubject can be used to override the subject of the
	// access token. If not set, the default will be used.
	OverrideAccessTokenSubject string

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, if one is issued. If zero, the default will be used.
	RefreshTokenValidUntil time.Time
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

	codeHash := hashValue(treq.Code)

	grant, err := s.config.Storage.GetGrantByAuthCode(ctx, codeHash)
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
	if *oldAuthCode != codeHash {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid code"}
	}

	// we have a validated code.
	if err := s.validateTokenClient(ctx, treq, grant.ClientID); err != nil {
		return nil, err
	}

	// If the client is public and we require pkce, reject it if there's no
	// verifier.
	clientOpts, err := s.config.Clients.ClientOpts(ctx, grant.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client opts: %w", err)
	}
	if !slices.Contains(clientOpts, ClientOptSkipPKCE) && treq.CodeVerifier == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, grant.Request.CodeChallenge) {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// we have a validated request. Call out to the handler to get the details.
	tr := &TokenRequest{
		Grant: grant,
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

	return s.buildTokenResponse(ctx, grant, tresp)
}

func (s *Server) refreshToken(ctx context.Context, treq *oauth2.TokenRequest) (_ *oauth2.TokenResponse, retErr error) {
	if treq.RefreshToken == "" {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidRequest, Description: "refresh token is required"}
	}

	refreshTokenHash := hashValue(treq.RefreshToken)

	grant, err := s.config.Storage.GetGrantByRefreshToken(ctx, refreshTokenHash)
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

	// storage should do this, but double check.
	if s.now().After(grant.ExpiresAt) {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "token expired"}
	}
	if refreshTokenHash != *oldRefreshToken {
		return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	// tresp, err := o.handler.RefreshToken(tr)
	// TODO - need to re-do this too.
	tr := &TokenRequest{
		Grant: grant,
	}
	tresp, err := s.config.TokenHandler(ctx, tr)
	if err != nil {
		var uaerr unauthorizedErr
		if errors.As(err, &uaerr); uaerr != nil && uaerr.Unauthorized() {
			return nil, &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeInvalidGrant, Description: uaerr.Error()}
		}
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}

	return s.buildTokenResponse(ctx, grant, tresp)
}

// buildTokenResponse creates the oauth token response for code and refresh.
// refreshSession can be nil, if it is and we should issue a refresh token, a
// new refresh session will be created.
func (s *Server) buildTokenResponse(ctx context.Context, grant *StoredGrant, tresp *TokenResponse) (_ *oauth2.TokenResponse, retErr error) {
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
		refreshTok = rand.Text()
		grant.RefreshToken = ptr(hashValue(refreshTok))
		saveGrant = true
	}

	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = s.now().Add(s.config.IDTokenValidity)
	}
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = s.now().Add(s.config.AccessTokenValidity)
	}

	// TODO - only try and issue an ID token if the openid scope was granted.

	idc := tresp.IDClaims
	if idc == nil {
		idc = &claims.RawIDClaims{}
	}

	idc.Issuer = s.config.Issuer
	idc.Subject = grant.UserID
	idc.Expiry = claims.UnixTime(idExp.Unix())
	idc.Audience = claims.StrOrSlice{grant.ClientID}
	idc.IssuedAt = claims.UnixTime(s.now().Unix())
	idc.AuthTime = claims.UnixTime(grant.GrantedAt.Unix())
	// TODO nonce
	// idc.Nonce = grant.Request.Nonce

	if tresp.OverrideIDSubject != "" {
		idc.Subject = tresp.OverrideIDSubject
	}

	// Apps should fill the profile info as needed.

	idjwt, err := idc.ToRawJWT()
	if err != nil {
		return nil, fmt.Errorf("creating identity token jwt: %w", err)
	}

	ac := tresp.AccessTokenClaims
	if ac == nil {
		ac = &claims.RawAccessTokenClaims{}
	}
	if ac.Extra == nil {
		ac.Extra = map[string]any{}
	}

	ac.Issuer = s.config.Issuer
	ac.Subject = grant.UserID
	ac.ClientID = grant.ClientID
	ac.Expiry = claims.UnixTime(atExp.Unix())
	ac.Audience = claims.StrOrSlice{s.config.Issuer}
	ac.IssuedAt = claims.UnixTime(s.now().Unix())
	ac.AuthTime = claims.UnixTime(grant.GrantedAt.Unix())
	ac.JWTID = uuid.Must(uuid.NewRandom()).String()
	ac.Extra[claimGrantID] = grant.ID.String()

	if tresp.OverrideAccessTokenSubject != "" {
		ac.Subject = tresp.OverrideAccessTokenSubject
	}

	acjwt, err := ac.ToRawJWT()
	if err != nil {
		return nil, fmt.Errorf("creating access token jwt: %w", err)
	}

	h, err := s.config.Keyset.HandleFor(SigningAlgRS256)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "getting handle", Cause: err}
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "creating signer from handle", Cause: err}
	}

	sidt, err := signer.SignAndEncode(idjwt)
	if err != nil {
		return nil, &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to sign id token", Cause: err}
	}

	sat, err := signer.SignAndEncode(acjwt)
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

func hashValue(v string) string {
	h := sha256.New()
	h.Write([]byte(v))
	return hex.EncodeToString(h.Sum(nil))
}

func ptr[T any](v T) *T {
	return &v
}

func verifyCodeChallenge(codeVerifier, storedCodeChallenge string) bool {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashedVerifier := h.Sum(nil)
	computedChallenge := base64.RawURLEncoding.EncodeToString(hashedVerifier)
	return computedChallenge == storedCodeChallenge
}
