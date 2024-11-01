package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

type TokenRequest struct {
	GrantType    GrantType
	Code         string
	RefreshToken string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	// CodeVerifier is the PKCE code verifier, if it was submitted with this
	// request.
	CodeVerifier string
}

// ParseTokenRequest parses the information from a request for an access token.
//
// https://tools.ietf.org/html/rfc6749#section-4.1.3
func ParseTokenRequest(req *http.Request) (*TokenRequest, error) {
	if req.Method != http.MethodPost {
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "method must be POST"}
	}

	tr := &TokenRequest{
		RedirectURI:  req.FormValue("redirect_uri"),
		Code:         req.FormValue("code"),
		RefreshToken: req.FormValue("refresh_token"),
		CodeVerifier: req.FormValue("code_verifier"),
	}

	// Auth the request
	// https://tools.ietf.org/html/rfc6749#section-2.3
	cid, cs, isBasic := req.BasicAuth()
	if isBasic {
		var err error
		tr.ClientID, err = url.QueryUnescape(cid)
		if err != nil {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "invalid encoding for client id"}
		}
		tr.ClientSecret, err = url.QueryUnescape(cs)
		if err != nil {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "invalid encoding for client secret"}
		}

	} else {
		tr.ClientID = req.FormValue("client_id")
		tr.ClientSecret = req.FormValue("client_secret")
	}

	switch req.FormValue("grant_type") {
	case string(GrantTypeAuthorizationCode):
		if tr.Code == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "code is required for authorization_code grant"}
		}
		if tr.RedirectURI == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "redirect_uri is required for authorization_code grant"}
		}
		tr.GrantType = GrantTypeAuthorizationCode

	case string(GrantTypeRefreshToken):
		// https://tools.ietf.org/html/rfc6749#section-6
		if tr.RefreshToken == "" {
			return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidRequest, Description: "refresh_token is required for refresh grant"}
		}
		tr.GrantType = GrantTypeRefreshToken

	default:
		return nil, &TokenError{ErrorCode: TokenErrorCodeInvalidGrant, Description: fmt.Sprintf("grant_type must be %s", GrantTypeAuthorizationCode)}
	}

	return tr, nil
}

// TokenResponse ref: https://tools.ietf.org/html/rfc6749#section-5.1
//
// this does eventually end up as JSON, but because of how we want to handle the
// extra params bit we don't tag this struct
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    time.Duration
	RefreshToken string
	Scopes       []string
	ExtraParams  map[string]interface{}
}

// WriteTokenResponse sends a response for the token endpoint.
//
// https://tools.ietf.org/html/rfc6749#section-5.1
func WriteTokenResponse(w http.ResponseWriter, resp *TokenResponse) error {
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")

	respJSON := resp.ExtraParams
	if respJSON == nil {
		respJSON = make(map[string]interface{})
	}

	respJSON["access_token"] = resp.AccessToken
	respJSON["token_type"] = resp.TokenType

	if resp.ExpiresIn != 0 {
		respJSON["expires_in"] = int(resp.ExpiresIn.Seconds())
	}
	if resp.RefreshToken != "" {
		respJSON["refresh_token"] = resp.RefreshToken
	}
	if resp.Scopes != nil {
		respJSON["scope"] = strings.Join(resp.Scopes, " ")
	}

	if err := json.NewEncoder(w).Encode(respJSON); err != nil {
		return fmt.Errorf("failed to write token response json body: %w", err)
	}

	return nil
}
