package oauth2as

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2as/internal/oauth2"
)

type AuthRequest struct {
	// ClientID is the client ID that is requesting authentication.
	ClientID string
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value. If provided, it will have been
	// validated.
	RedirectURI string
	// State is the state value that was passed in the request.
	State string
	// Scopes is the list of scopes that the client is requesting.
	Scopes []string
	// CodeChallenge is the PKCE code challenge. If it is provided, it will be
	// S256 format. If not provided, it will be an empty string.
	CodeChallenge string
	// ACRValues is the list of ACR values that the client is requesting.
	ACRValues []string

	// Raw is the raw URL values that were passed in the request.
	Raw url.Values
}

func (s *Server) ParseAuthRequest(req *http.Request) (*AuthRequest, error) {
	// Note - we don't strictly handle errors as the spec says. We always return
	// them to the user to deal with, and never redirect back. Maybe we should
	// do that at some point, but I'm leaning towards not.
	authreq, err := oauth2.ParseAuthRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth request: %w", err)
	}

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authreq.RedirectURI, err)
	}

	cidok, err := s.config.Clients.IsValidClientID(authreq.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error checking client ID %s: %w", authreq.ClientID, err)
	}
	if !cidok {
		return nil, fmt.Errorf("client ID %s is not valid", authreq.ClientID)
	}

	redirs, err := s.config.Clients.RedirectURIs(authreq.ClientID)
	if err != nil {
		return nil, fmt.Errorf("error getting redirect URIs for client ID %s: %w", authreq.ClientID, err)
	}

	// Handle the case where no redirect URI is provided
	if authreq.RedirectURI == "" {
		if len(redirs) != 1 {
			return nil, fmt.Errorf("client ID %s has multiple redirect URIs, but none were provided", authreq.ClientID)
		}
		// Use the single registered redirect URI
		authreq.RedirectURI = redirs[0]
		// Re-parse the redirect URI since we changed it
		redir, err = url.Parse(authreq.RedirectURI)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authreq.RedirectURI, err)
		}
	} else {
		// Validate the provided redirect URI
		if !isValidRedirectURI(authreq.RedirectURI, redirs) {
			return nil, fmt.Errorf("redirect URI %s is not valid for client ID %s", authreq.RedirectURI, authreq.ClientID)
		}
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
}

func (s *Server) GrantAuth(ctx context.Context, grant *AuthGrant) (redirectURI string, _ error) {
	if grant.UserID == "" {
		return "", fmt.Errorf("user ID is required")
	}
	if grant.Request == nil {
		return "", fmt.Errorf("auth request is required")
	}

	code := rand.Text()
	codeHash := hashValue(code)

	sg := &StoredGrant{
		ID:            uuid.New(), // do we want v7? would that leak info?
		UserID:        grant.UserID,
		ClientID:      grant.Request.ClientID,
		GrantedScopes: grant.GrantedScopes,
		AuthCode:      &codeHash,
		Request:       grant.Request,
		GrantedAt:     s.now(),
		ExpiresAt:     s.now().Add(s.config.CodeValidityTime),
	}

	if err := s.config.Storage.CreateGrant(ctx, sg); err != nil {
		return "", fmt.Errorf("failed to create grant: %w", err)
	}

	// Handle the case where no redirect URI is provided
	redirs, err := s.config.Clients.RedirectURIs(grant.Request.ClientID)
	if err != nil {
		return "", fmt.Errorf("error getting redirect URIs for client ID %s: %w", grant.Request.ClientID, err)
	}

	if grant.Request.RedirectURI == "" {
		if len(redirs) != 1 {
			return "", fmt.Errorf("client ID %s has multiple redirect URIs, but none were provided", grant.Request.ClientID)
		}
		// Use the single registered redirect URI
		grant.Request.RedirectURI = redirs[0]
	} else {
		// Validate the provided redirect URI
		if !isValidRedirectURI(grant.Request.RedirectURI, redirs) {
			return "", fmt.Errorf("redirect URI %s is not valid for client ID %s", grant.Request.RedirectURI, grant.Request.ClientID)
		}
	}

	redir, err := url.Parse(grant.Request.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse authreq's URI: %w", err)
	}

	codeResp := &oauth2.CodeAuthResponse{
		RedirectURI: redir,
		State:       grant.Request.State,
		Code:        code,
	}

	return codeResp.ToRedirectURI().String(), nil
}
