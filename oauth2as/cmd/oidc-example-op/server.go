package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"strings"

	"net/http"

	"github.com/lstoll/oauth2as"
	"github.com/lstoll/oauth2ext/claims"
)

type server struct {
	core *oauth2as.Server
}

const loginPage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<h1>Log in to IDP</h1>
		<form action="/finish" method="POST">
			<input type="hidden" name="auth_request" value="{{ .auth_request_data }}">
			<p>Subject: <input type="text" name="subject" value="auser" required size="15"></p>
			<p>Granted Scopes (space delimited): <input type="text" name="scopes" value="{{ .scopes }}" size="15"></p>
			<p>ACR: <input type="text" name="acr" size="15"></p>
			<p>AMR (comma delimited): <input type="text" name="amr" value="{{ .amr }}" size="15"></p>
			<p>Userinfo: <textarea name="userinfo" rows="10" cols="30">{"name": "A User"}</textarea></p>
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var loginTmpl = template.Must(template.New("loginPage").Parse(loginPage))

func (s *server) SetCore(core *oauth2as.Server) {
	s.core = core
}

func (s *server) StartAuthorization(w http.ResponseWriter, req *http.Request) {
	// Parse the authorization request
	authReq, err := s.core.ParseAuthRequest(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse auth request: %v", err), http.StatusBadRequest)
		return
	}

	// Serialize the auth request to store in the form
	authReqData, err := json.Marshal(authReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to serialize auth request: %v", err), http.StatusInternalServerError)
		return
	}
	authReqEncoded := base64.StdEncoding.EncodeToString(authReqData)

	var acr string
	if len(authReq.ACRValues) > 0 {
		acr = authReq.ACRValues[0]
	}
	tmplData := map[string]interface{}{
		"auth_request_data": authReqEncoded,
		"acr":               acr,
		"scopes":            strings.Join(authReq.Scopes, " "),
	}

	if err := loginTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) finishAuthorization(w http.ResponseWriter, req *http.Request) {
	// Retrieve and deserialize the auth request
	authReqEncoded := req.FormValue("auth_request")
	if authReqEncoded == "" {
		http.Error(w, "missing auth request data", http.StatusBadRequest)
		return
	}

	authReqData, err := base64.StdEncoding.DecodeString(authReqEncoded)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decode auth request: %v", err), http.StatusBadRequest)
		return
	}

	var authReq oauth2as.AuthRequest
	if err := json.Unmarshal(authReqData, &authReq); err != nil {
		http.Error(w, fmt.Sprintf("failed to deserialize auth request: %v", err), http.StatusBadRequest)
		return
	}

	// Create authorization grant using the actual auth request
	grant := &oauth2as.AuthGrant{
		Request:       &authReq,
		GrantedScopes: strings.Split(req.FormValue("scopes"), " "),
		UserID:        req.FormValue("subject"),
	}

	// Grant the authorization
	redirectURI, err := s.core.GrantAuth(req.Context(), grant)
	if err != nil {
		slog.ErrorContext(req.Context(), "error authorizing", "err", err)
		http.Error(w, "error authorizing", http.StatusInternalServerError)
		return
	}

	// Redirect to the client
	http.Redirect(w, req, redirectURI, http.StatusFound)
}

func (s *server) handleToken(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
	return &oauth2as.TokenResponse{
		IDClaims: &claims.RawIDClaims{
			Subject: req.Grant.UserID,
		},
		AccessTokenClaims: &claims.RawAccessTokenClaims{
			Subject: req.Grant.UserID,
		},
	}, nil
}

func (s *server) handleUserinfo(_ context.Context, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
	return &oauth2as.UserinfoResponse{
		Identity: &claims.RawIDClaims{
			Subject: uireq.Subject,
		},
	}, nil
}
