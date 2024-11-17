package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"strings"

	"net/http"

	"github.com/google/uuid"
	"github.com/lstoll/oidcop"
)

const (
	authReqIDCookieName = "authReqID"
)

type metadata struct {
	Userinfo map[string]any `json:"userinfo"`
}

var _ oidcop.AuthHandlers = (*server)(nil)

type server struct {
	authorizer oidcop.Authorizer
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

func (s *server) SetAuthorizer(at oidcop.Authorizer) {
	s.authorizer = at
}

func (s *server) StartAuthorization(w http.ResponseWriter, req *http.Request, authReq *oidcop.AuthorizationRequest) {
	// set a cookie with the auth ID, so we can track it.
	aidc := &http.Cookie{
		Name:   authReqIDCookieName,
		Value:  authReq.ID.String(),
		MaxAge: 600,
	}
	http.SetCookie(w, aidc)

	var acr string
	if len(authReq.ACRValues) > 0 {
		acr = authReq.ACRValues[0]
	}
	tmplData := map[string]interface{}{
		"acr":    acr,
		"scopes": strings.Join(authReq.Scopes, " "),
	}

	if err := loginTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) finishAuthorization(w http.ResponseWriter, req *http.Request) {
	authReqCookie, err := req.Cookie(authReqIDCookieName)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get auth id cookie: %v", err), http.StatusInternalServerError)
		return
	}
	authReqUUID, err := uuid.Parse(authReqCookie.Value)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid auth req ID format: %v", err), http.StatusBadRequest)
		return
	}

	var amr []string
	if req.FormValue("amr") != "" {
		amr = strings.Split(req.FormValue("amr"), ",")
	}

	meta := &metadata{
		Userinfo: map[string]interface{}{},
	}
	if err := json.Unmarshal([]byte(req.FormValue("userinfo")), &meta.Userinfo); err != nil {
		http.Error(w, fmt.Sprintf("failed to unmarshal userinfo: %v", err), http.StatusInternalServerError)
		return
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal metadata: %v", err), http.StatusInternalServerError)
		return
	}

	if err := s.authorizer.Authorize(w, req, authReqUUID, &oidcop.Authorization{
		Subject:  req.FormValue("subject"),
		Scopes:   strings.Split(req.FormValue("scopes"), " "),
		ACR:      req.FormValue("acr"),
		AMR:      amr,
		Metadata: mb,
	}); err != nil {
		slog.ErrorContext(req.Context(), "error authorizing", "err", err)
		http.Error(w, "error authorizing", http.StatusInternalServerError)
	}
}

func (s *server) Token(req *oidcop.TokenRequest) (*oidcop.TokenResponse, error) {
	return &oidcop.TokenResponse{
		Identity: &oidcop.Identity{},
	}, nil
}

func (s *server) RefreshToken(req *oidcop.RefreshTokenRequest) (*oidcop.TokenResponse, error) {
	return &oidcop.TokenResponse{
		Identity: &oidcop.Identity{},
	}, nil
}

func (s *server) Userinfo(w io.Writer, uireq *oidcop.UserinfoRequest) (*oidcop.UserinfoResponse, error) {
	return &oidcop.UserinfoResponse{
		Identity: &oidcop.Identity{},
	}, nil
}
