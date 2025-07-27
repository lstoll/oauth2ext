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

func (s *Server) GrantAuth(grant *AuthGrant) (redirectURI string, _ error) {
	/* func (s *Server) finishAuthorization(w http.ResponseWriter, req *http.Request, authReqID uuid.UUID, auth *Authorization) error {


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
	*/

	/*
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

	*/
	return "", nil
}
