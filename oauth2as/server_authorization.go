package oauth2as

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"lds.li/oauth2ext/oauth2as/internal/oauth2"
)

type AuthRequest struct {
	// ClientID is the client ID that is requesting authentication.
	ClientID string `json:"clientID,omitzero"`
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value. If provided, it will have been
	// validated.
	RedirectURI string `json:"redirectURI,omitzero"`
	// State is the state value that was passed in the request.
	State string `json:"state,omitzero"`
	// Scopes is the list of scopes that the client is requesting.
	Scopes []string `json:"scopes,omitzero"`
	// CodeChallenge is the PKCE code challenge. If it is provided, it will be
	// S256 format. If not provided, it will be an empty string.
	CodeChallenge string `json:"codeChallenge,omitzero"`
	// ACRValues is the list of ACR values that the client is requesting.
	ACRValues []string `json:"acrValues,omitzero"`

	// Raw is the raw URL values that were passed in the request.
	Raw url.Values `json:"raw,omitzero"`
}

func (s *Server) ParseAuthRequest(req *http.Request) (*AuthRequest, error) {
	// Note: Error handling deviates from the spec - errors are returned directly
	// rather than redirected to the client's redirect_uri.
	// TODO - consider if we should fix this.
	authreq, err := oauth2.ParseAuthRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth request: %w", err)
	}

	cidok, err := s.config.Clients.IsValidClientID(req.Context(), authreq.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error checking client ID %s: %w", authreq.ClientID, err)
	}
	if !cidok {
		return nil, fmt.Errorf("client ID %s is not valid", authreq.ClientID)
	}

	redirs, err := s.config.Clients.RedirectURIs(req.Context(), authreq.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error getting redirect URIs for client ID %s: %w", authreq.ClientID, err)
	}

	// Validate and resolve the redirect URI
	validatedRedirectURI, err := validateAndResolveRedirectURI(authreq.RedirectURI, redirs, authreq.ClientID)
	if err != nil {
		return nil, err
	}
	authreq.RedirectURI = validatedRedirectURI

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authreq.RedirectURI, err)
	}

	switch authreq.ResponseType {
	case oauth2.ResponseTypeCode:
	default:
		return nil, fmt.Errorf("response type %s is not supported", authreq.ResponseType)
	}

	var acrValues []string
	if authreq.Raw.Get("acr_values") != "" {
		acrValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}

	return &AuthRequest{
		ClientID:      authreq.ClientID,
		RedirectURI:   redir.String(),
		State:         authreq.State,
		Scopes:        authreq.Scopes,
		CodeChallenge: authreq.CodeChallenge,
		ACRValues:     acrValues,
	}, nil
}

type AuthGrant struct {
	// Request is the corresponding authorization request that we are granting
	// access for.
	Request *AuthRequest
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string
	// UserID is the user ID that was granted access. This is used to form the subject
	// claim, and is provided on subsequent actions.
	UserID string
	// Metadata is arbitrary metadata that can be stored with the grant. Can be
	// used for auditing or tracking other information that is associated with
	// the grant. This is not sensitive, and can be accessed at any time.
	Metadata []byte
	// EncryptedMetadata is the encrypted metadata that can be stored with the
	// grant. This is only available to token callbacks. Can be used to store
	// sensitive, grant-specific information like upstream auth tokens.
	EncryptedMetadata []byte
}

func (s *Server) GrantAuth(ctx context.Context, grant *AuthGrant) (redirectURI string, _ error) {
	if grant.UserID == "" {
		return "", fmt.Errorf("user ID is required")
	}
	if grant.Request == nil {
		return "", fmt.Errorf("auth request is required")
	}

	expiresAt := s.now().Add(s.config.MaxRefreshTime)
	if s.config.MaxRefreshTime == 0 {
		expiresAt = s.now().Add(s.config.CodeValidityTime)
	}

	sg := &StoredGrant{
		UserID:        grant.UserID,
		ClientID:      grant.Request.ClientID,
		GrantedScopes: grant.GrantedScopes,
		Request:       grant.Request,
		GrantedAt:     s.now(),
		ExpiresAt:     expiresAt, // Grant has absolute lifetime
		Metadata:      grant.Metadata,
	}

	loadedGrant := &loadedAuthCodeGrant{
		grant:             sg,
		decryptedMetadata: grant.EncryptedMetadata,
	}

	_, authCodeString, err := s.putGrantWithAuthCode(ctx, loadedGrant, s.now().Add(s.config.CodeValidityTime))
	if err != nil {
		return "", fmt.Errorf("failed to put grant with auth code: %w", err)
	}

	// Validate and resolve the redirect URI
	redirs, err := s.config.Clients.RedirectURIs(ctx, grant.Request.ClientID)
	if err != nil {
		return "", fmt.Errorf("error getting redirect URIs for client ID %s: %w", grant.Request.ClientID, err)
	}

	redirURI, err := validateAndResolveRedirectURI(grant.Request.RedirectURI, redirs, grant.Request.ClientID)
	if err != nil {
		return "", err
	}

	redir, err := url.Parse(redirURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse authreq's URI: %w", err)
	}

	codeResp := &oauth2.CodeAuthResponse{
		RedirectURI: redir,
		State:       grant.Request.State,
		Code:        authCodeString,
	}

	return codeResp.ToRedirectURI().String(), nil
}

// validateAndResolveRedirectURI validates the provided redirect URI against the
// list of registered redirects for a client. If no redirect URI is provided and
// the client has exactly one registered redirect, it returns that redirect.
// Otherwise, it validates that the provided redirect is in the registered list.
func validateAndResolveRedirectURI(redirectURI string, registeredRedirects []string, clientID string) (string, error) {
	if redirectURI == "" {
		if len(registeredRedirects) != 1 {
			return "", fmt.Errorf("client ID %s has multiple redirect URIs, but none were provided", clientID)
		}
		// Use the single registered redirect URI
		return registeredRedirects[0], nil
	}

	// Validate the provided redirect URI
	if !isValidRedirectURI(redirectURI, registeredRedirects) {
		return "", fmt.Errorf("redirect URI %s is not valid for client ID %s", redirectURI, clientID)
	}
	return redirectURI, nil
}
