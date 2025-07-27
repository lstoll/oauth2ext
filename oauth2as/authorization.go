package oauth2as

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	if authreq.RedirectURI == "" && len(redirs) != 1 {
		return nil, fmt.Errorf("client ID %s has multiple redirect URIs, but none were provided", authreq.ClientID)
	}

	if !isValidRedirectURI(authreq.RedirectURI, redirs) {
		return nil, fmt.Errorf("redirect URI %s is not valid for client ID %s", authreq.RedirectURI, authreq.ClientID)
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
