package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"sync"

	"net/http"

	"github.com/lstoll/oidc"
	"github.com/lstoll/oidc/internal"
	"golang.org/x/oauth2"
)

const (
	stateCookie = "state"
)

type server struct {
	provider *oidc.Provider
	oa2Cfg   oauth2.Config
	mux      *http.ServeMux
	muxSetup sync.Once

	// pkceChallenges maps the state to the challenge.
	pkceChallenges map[string]string
}

const homePage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<h1>Start auth flow</h1>
		<form action="/start" method="POST">
    		<input type="submit" value="Submit">
		</form>
	</body>
</html>`

var homeTmpl = template.Must(template.New("loginPage").Parse(homePage))

func (s *server) home(w http.ResponseWriter, req *http.Request) {
	tmplData := map[string]any{}

	if err := homeTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

// start the actual flow. this builds up the request and sends the user on
func (s *server) start(w http.ResponseWriter, req *http.Request) {
	// track a random state var to prevent CSRF
	state := internal.RandText()
	sc := &http.Cookie{
		Name:   stateCookie,
		Value:  state,
		MaxAge: 60,
	}
	http.SetCookie(w, sc)

	verifier := oauth2.GenerateVerifier()
	url := s.oa2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	// it is not safe to give this to the end user. Associating it with a
	// secured session would be good, for this app we just track it server side
	// against the state.
	s.pkceChallenges[state] = verifier

	http.Redirect(w, req, url, http.StatusSeeOther)
}

const callbackPage = `<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>LOG IN</title>
	</head>
	<body>
		<p>access_token: {{ .access_token }}</p>
		<p>raw id_token: {{ .id_token }}</p>
		<p>claims: {{ .claims }}</p>
	</body>
</html>`

var callbackTmpl = template.Must(template.New("loginPage").Parse(callbackPage))

func (s *server) callback(w http.ResponseWriter, req *http.Request) {
	statec, err := req.Cookie(stateCookie)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get state cookie: %v", err), http.StatusInternalServerError)
		return
	}

	if errMsg := req.FormValue("error"); errMsg != "" {
		http.Error(w, fmt.Sprintf("error returned to callback %s: %s", errMsg, req.FormValue("error_description")), http.StatusInternalServerError)
		return
	}

	code := req.FormValue("code")
	if code == "" {
		http.Error(w, "no code in callback response", http.StatusBadRequest)
		return
	}

	gotState := req.FormValue("state")
	if gotState == "" || gotState != statec.Value {
		http.Error(w, fmt.Sprintf("returned state %q doesn't match request state %q", gotState, statec.Value), http.StatusBadRequest)
		return
	}

	chall, ok := s.pkceChallenges[gotState]
	if !ok {
		http.Error(w, "no PKCE challenge found for state", http.StatusBadRequest)
		return
	}

	token, err := s.oa2Cfg.Exchange(req.Context(), code, oauth2.VerifierOption(chall))
	if err != nil {
		http.Error(w, fmt.Sprintf("error exchanging code %q for token: %v", code, err), http.StatusInternalServerError)
		return
	}

	tmplData := map[string]any{
		"access_token": token.AccessToken,
	}

	idt, hasIDToken := oidc.GetIDToken(token)
	if hasIDToken {
		jwt, err := s.provider.VerifyIDToken(req.Context(), token, oidc.IDTokenValidationOpts{
			Audience: string(s.oa2Cfg.ClientID),
		})
		if err != nil {
			slog.ErrorContext(req.Context(), "verifying ID token", "err", err)
			http.Error(w, fmt.Sprintf("verifying token: %v", err), http.StatusInternalServerError)
			return
		}

		jwtjson, err := jwt.JSONPayload()
		if err != nil {
			slog.ErrorContext(req.Context(), "getting ID token payload", "err", err)
			http.Error(w, fmt.Sprintf("getting ID token payload: %v", err), http.StatusInternalServerError)
			return
		}
		mapclaims := make(map[string]any)
		if err := json.Unmarshal(jwtjson, &mapclaims); err != nil {
			slog.ErrorContext(req.Context(), "unmarshaling payload to map", "err", err)
			http.Error(w, fmt.Sprintf("unmarshaling payload to map: %v", err), http.StatusInternalServerError)
			return
		}

		cljson, err := json.MarshalIndent(mapclaims, "", "  ")
		if err != nil {
			http.Error(w, "couldn't serialize claims", http.StatusBadRequest)
			return
		}

		tmplData["id_token"] = idt
		tmplData["claims"] = string(cljson)
	}

	if err := callbackTmpl.Execute(w, tmplData); err != nil {
		http.Error(w, fmt.Sprintf("failed to render template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.muxSetup.Do(func() {
		s.mux = http.NewServeMux()
		s.mux.HandleFunc("/", s.home)
		s.mux.HandleFunc("/start", s.start)
		s.mux.HandleFunc("/callback", s.callback)
	})

	s.mux.ServeHTTP(w, req)
}
