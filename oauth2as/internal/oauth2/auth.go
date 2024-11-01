package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ResponseType string

const (
	ResponseTypeCode     ResponseType = "code"
	ResponseTypeImplicit ResponseType = "token"

	CodeChallengeMethodS256 = "S256"
)

type AuthRequest struct {
	ClientID string
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value
	RedirectURI  string
	State        string
	Scopes       []string
	ResponseType ResponseType
	// CodeChallenge is the PKCE code challenge. If it is provided, it will be
	// S256 format.
	CodeChallenge string

	// Raw is the full, unprocessed set of values passed to this request.
	Raw url.Values
}

// ParseAuthRequest can be used to process an oauth2 authentication request,
// returning information about it. It can handle both the code and implicit auth
// types. If an error is returned, it should be passed to the user via
// writeError
//
// https://tools.ietf.org/html/rfc6749#section-4.1.1
// https://tools.ietf.org/html/rfc6749#section-4.2.1
func ParseAuthRequest(req *http.Request) (authReq *AuthRequest, err error) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return nil, &HTTPError{Code: http.StatusBadRequest, Message: "method must be POST or GET"}
	}

	rts := req.FormValue("response_type")
	cid := req.FormValue("client_id")
	ruri := req.FormValue("redirect_uri")
	scope := req.FormValue("scope")
	state := req.FormValue("state")
	codeChallenge := req.FormValue("code_challenge")
	codeChallengeMethod := req.FormValue("code_challenge_method")

	var rt ResponseType
	switch rts {
	case string(ResponseTypeCode):
		rt = ResponseTypeCode
	case string(ResponseTypeImplicit):
		rt = ResponseTypeImplicit
	default:
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: `response_type must be "code" or "token"`,
			RedirectURI: ruri,
		}
	}

	if cid == "" {
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: "client_id must be specified",
			RedirectURI: ruri,
		}
	}

	if codeChallenge != "" && codeChallengeMethod != CodeChallengeMethodS256 {
		return nil, &AuthError{
			State:       state,
			Code:        AuthErrorCodeInvalidRequest,
			Description: fmt.Sprintf(`only code_challenge type "%s" supported`, CodeChallengeMethodS256),
			RedirectURI: ruri,
		}

	}

	return &AuthRequest{
		ClientID:      cid,
		RedirectURI:   ruri,
		State:         state,
		Scopes:        strings.Split(strings.TrimSpace(scope), " "),
		ResponseType:  rt,
		Raw:           req.Form,
		CodeChallenge: codeChallenge,
	}, nil
}

type CodeAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Code        string
}

// SendCodeAuthResponse sends the appropriate response to an auth request of
// response_type code, aka "Code flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.1.2
func SendCodeAuthResponse(w http.ResponseWriter, req *http.Request, resp *CodeAuthResponse) {
	redir := authResponse(resp.RedirectURI, resp.State)
	v := redir.Query()
	v.Add("code", resp.Code)
	redir.RawQuery = v.Encode()
	http.Redirect(w, req, redir.String(), http.StatusFound)
}

type TokenType string

const ( // https://tools.ietf.org/html/rfc6749#section-7.1 , https://tools.ietf.org/html/rfc6750
	TokenTypeBearer TokenType = "Bearer"
)

type TokenAuthResponse struct {
	RedirectURI *url.URL
	State       string
	Token       string
	TokenType   TokenType
	Scopes      []string
	ExpiresIn   time.Duration
}

// SendTokenAuthResponse sends the appropriate response to an auth request of
// response_type token, aka "Implicit flow"
//
// https://tools.ietf.org/html/rfc6749#section-4.2.2
func SendTokenAuthResponse(w http.ResponseWriter, req *http.Request, resp *TokenAuthResponse) {
	redir := authResponse(resp.RedirectURI, resp.State)
	v := redir.Query()
	v.Add("access_token", resp.Token)
	v.Add("token_type", string(resp.TokenType))
	if resp.ExpiresIn != 0 {
		v.Add("expires_in", fmt.Sprintf("%d", int(resp.ExpiresIn.Seconds())))
	}
	if resp.Scopes != nil {
		v.Add("scope", strings.Join(resp.Scopes, " "))
	}
	redir.RawQuery = v.Encode()
	http.Redirect(w, req, redir.String(), http.StatusFound)
}

func authResponse(redir *url.URL, state string) *url.URL {
	v := redir.Query()
	if state != "" {
		v.Add("state", state)
	}
	redir.RawQuery = v.Encode()
	return redir
}
