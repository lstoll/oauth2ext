package middleware

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
)

const (
	defaultSessionName = "oidc-middleware"

	sessionKeyOIDCState        = "oidc-state"
	sessionKeyOIDCReturnTo     = "oidc-return-to"
	sessionKeyOIDCIDToken      = "oidc-id-token"
	sessionKeyOIDCRefreshToken = "oidc-refresh-token"
)

// GorillaSessions is a wrapper around a gorilla sessions store, to comply with
// the new sessions interface.
//
// Deprecated: this is most provided for backwards compatibility, or an example
// for an implementation. It will be removed one day.
type GorillaSessions struct {
	// Store is the gorilla sessions store to use
	Store sessions.Store
	// SessionName is a name used for the session, If not set, a default is used.
	SessionName string
}

func (g *GorillaSessions) GetSession(r *http.Request) (*SessionDataV2, error) {
	if g.Store == nil {
		return nil, fmt.Errorf("store must be set")
	}
	if g.SessionName == "" {
		g.SessionName = defaultSessionName
	}

	session, err := g.Store.Get(r, g.SessionName)
	if err != nil {
		return nil, fmt.Errorf("getting session %s: %w", g.SessionName, err)
	}

	state, _ := session.Values[sessionKeyOIDCState].(string)
	returnTo, _ := session.Values[sessionKeyOIDCReturnTo].(string)
	rawIDToken, _ := session.Values[sessionKeyOIDCIDToken].(string)
	refreshToken, _ := session.Values[sessionKeyOIDCRefreshToken].(string)

	return &SessionDataV2{
		State:        state,
		ReturnTo:     returnTo,
		IDToken:      rawIDToken,
		RefreshToken: refreshToken,
	}, nil

}

func (g *GorillaSessions) SaveSession(w http.ResponseWriter, r *http.Request, d *SessionDataV2) error {
	if g.Store == nil {
		return fmt.Errorf("store must be set")
	}
	if g.SessionName == "" {
		g.SessionName = defaultSessionName
	}

	session, _ := g.Store.Get(r, g.SessionName)
	session.Values[sessionKeyOIDCState] = d.State
	session.Values[sessionKeyOIDCReturnTo] = d.ReturnTo
	session.Values[sessionKeyOIDCIDToken] = d.IDToken
	session.Values[sessionKeyOIDCRefreshToken] = d.RefreshToken

	// stick the fields in, and go
	if err := sessions.Save(r, w); err != nil {
		return fmt.Errorf("saving session: %w", err)
	}
	return nil
}
