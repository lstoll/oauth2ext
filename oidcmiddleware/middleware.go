package oidcmiddleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oidc"
	"golang.org/x/oauth2"
)

const loginStateExpiresAfter = 5 * time.Minute

// DefaultKeyRefreshIterval is the default interval we try and refresh signing
// keys from the issuer.
const DefaultKeyRefreshIterval = 1 * time.Hour

type tokenContextKey struct{}

var baseLogAttr = slog.String("component", "oidc-middleware")

func errAttr(err error) slog.Attr { return slog.String("err", err.Error()) }

// SessionData contains the data this middleware needs to save/restore across
// requests. This should be stored using a method that does not reveal the
// contents to the end user in any way.
type SessionData struct {
	// Logins tracks state for in-progress logins.
	Logins []SessionDataLogin `json:"logins,omitempty"`
	// Token contains the issued token from a successful authentication flow.
	Token *oidc.TokenWithID `json:"token,omitempty"`
}

type SessionDataLogin struct {
	// State for an in-progress auth flow.
	State string `json:"oidc_state,omitempty"`
	// PKCEChallenge for the in-progress auth flow
	PKCEChallenge string `json:"pkce_challenge,omitempty"`
	// ReturnTo is where we should navigate to at the end of the flow
	ReturnTo string `json:"oidc_return_to,omitempty"`
	// Expires is when this can be discarded, Unix time.
	Expires int `json:"expires,omitempty"`
}

// SessionStore are used for managing state across requests.
type SessionStore interface {
	// GetOIDCSession should always return a valid, usable session. If the session does not
	// exist, it should be empty. error indicates that there was a failure that
	// we should not proceed from.
	GetOIDCSession(*http.Request) (*SessionData, error)
	// SaveOIDCSession should store the updated session. If the session data is nil, the
	// session should be deleted.
	SaveOIDCSession(http.ResponseWriter, *http.Request, *SessionData) error
}

// Handler wraps another http.Handler, protecting it with OIDC authentication.
type Handler struct {
	// Provider is the OIDC provider we verify tokens against. Required.
	Provider *oidc.Provider
	// OAuth2Config are the options used for the oauth2 flow. Required.
	OAuth2Config *oauth2.Config
	// AuthCodeOptions options that can be passed when creating the auth code
	// URL. This can be used to request ACRs or other items.
	AuthCodeOptions []oauth2.AuthCodeOption
	// SessionStore are used for managing state that we need to persist across
	// requests. It needs to be able to store ID and refresh tokens, plus a
	// small amount of additional data. Required.
	SessionStore SessionStore
	// BaseURL sets the base URL for this app, users will be redirect on login
	// here if the return to URL was not tracked or login was triggered from a
	// non-GET method request.
	BaseURL string
}

// NewFromDiscovery will construct a Handler by discovering the configuration
// from the Issuer. If the sessStore is nil, Cookies will be used. The handler
// can be customized after calling this.
func NewFromDiscovery(ctx context.Context, sessStore SessionStore, issuer, clientID, clientSecret, redirectURL string) (*Handler, error) {
	provider, err := oidc.DiscoverProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering provider: %w", err)
	}

	if sessStore == nil {
		sessStore = &Cookiestore{}
	}

	return &Handler{
		Provider: provider,
		OAuth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID},
			RedirectURL:  redirectURL,
		},
		SessionStore: sessStore,
	}, nil
}

// Wrap returns an http.Handler that wraps the given http.Handler and
// provides OIDC authentication.
func (h *Handler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.SessionStore == nil {
			slog.ErrorContext(r.Context(), "Uninitialized session store", baseLogAttr)
			http.Error(w, "Uninitialized session store", http.StatusInternalServerError)
			return
		}
		session, err := h.SessionStore.GetOIDCSession(r)
		if err != nil {
			slog.ErrorContext(r.Context(), "Failed to get session", baseLogAttr, errAttr(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check for a user that's already authenticated
		tok, idclaims := h.authenticateExisting(r, session)
		if tok != nil {
			if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Authentication successful
			r = r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, contextData{
				token:    tok,
				idclaims: idclaims,
			}))
			next.ServeHTTP(w, r)
			return
		}

		// Check for an authentication request finishing
		returnTo, err := h.authenticateCallback(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if returnTo != "" {
			if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, returnTo, http.StatusSeeOther)
			return
		}

		// Not authenticated. Kick off an auth flow.
		redirectURL := h.startAuthentication(r, session)

		if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})
}

// authenticateExisting returns (claims, nil) if the user is authenticated,
// (nil, error) if a fatal error occurs, or (nil, nil) if the user is not
// authenticated but no fatal error occurred.
//
// This function may modify the session if a token is refreshed, so it must be
// saved afterward.
func (h *Handler) authenticateExisting(r *http.Request, session *SessionData) (*oauth2.Token, *jwt.IDClaims) {
	ctx := r.Context()

	if session.Token == nil {
		return nil, nil
	}

	// we always verify, as in the cookie store case the integrity of the data
	// is not trusted.
	jwt, err := h.getIDTokenVerifier().Verify(ctx, session.Token.Token)
	if err != nil {
		// Attempt to refresh the token
		if session.Token.RefreshToken == "" {
			return nil, nil
		}
		token, err := h.OAuth2Config.TokenSource(ctx, session.Token.Token).Token()
		if err != nil {
			return nil, nil
		}
		jwt, err = h.getIDTokenVerifier().Verify(ctx, token)
		if err != nil {
			return nil, nil
		}
	}

	// create a new token with refresh token stripped. We ultimtely don't want
	// downstream consumers refreshing themselves, as it will likely invalidate
	// ours. This should mainly be used during a HTTP request lifecycle too, so
	// we would have done the job of refreshing if needed.
	retTok := *session.Token.Token
	retTok.RefreshToken = ""
	return &retTok, jwt
}

// authenticateCallback returns (returnTo, nil) if the user is authenticated,
// ("", error) if a fatal error occurs, or ("", nil) if the user is not
// authenticated but a fatal error did not occur.
//
// This function may modify the session if a token is authenticated, so it must be
// saved afterward.
func (h *Handler) authenticateCallback(r *http.Request, session *SessionData) (string, error) {
	ctx := r.Context()

	if r.Method != http.MethodGet {
		return "", nil
	}

	if qerr := r.URL.Query().Get("error"); qerr != "" {
		qdesc := r.URL.Query().Get("error_description")
		return "", fmt.Errorf("%s: %s", qerr, qdesc)
	}

	// If state or code are missing, this is not a callback
	state := r.URL.Query().Get("state")
	if state == "" {
		return "", nil
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", nil
	}

	var foundLogin *SessionDataLogin
	for _, sl := range session.Logins {
		if state != "" && sl.State == state {
			foundLogin = &sl
		}
	}
	if foundLogin == nil {
		return "", fmt.Errorf("state did not match")
	}

	opts := h.AuthCodeOptions
	if slices.Contains(h.Provider.Metadata.CodeChallengeMethodsSupported, "S256") {
		opts = append(opts, oauth2.VerifierOption(foundLogin.PKCEChallenge))
	}

	token, err := h.OAuth2Config.Exchange(ctx, code, opts...)
	if err != nil {
		return "", err
	}

	// TODO(lstoll) do we want to verify the ID token here? was retrieved from a
	// trusted source....
	_, err = h.getIDTokenVerifier().Verify(ctx, token)
	if err != nil {
		return "", fmt.Errorf("verifying id_token failed: %w", err)
	}

	session.Token = &oidc.TokenWithID{Token: token}

	returnTo := foundLogin.ReturnTo
	if returnTo == "" {
		returnTo = h.BaseURL
		if returnTo == "" {
			returnTo = "/"
		}
	}

	session.Logins = slices.DeleteFunc(session.Logins, func(sl SessionDataLogin) bool {
		return sl.State == state
	})

	return returnTo, nil
}

func (h *Handler) startAuthentication(r *http.Request, session *SessionData) string {
	session.Token = nil

	var (
		state         = rand.Text()
		pkceChallenge string
		returnTo      string
	)

	opts := h.AuthCodeOptions
	if slices.Contains(h.Provider.Metadata.CodeChallengeMethodsSupported, "S256") {
		pkceChallenge = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pkceChallenge))
	}

	if r.Method == http.MethodGet {
		returnTo = r.URL.RequestURI()
	}
	session.Logins = append(session.Logins, SessionDataLogin{
		State:         state,
		PKCEChallenge: pkceChallenge,
		ReturnTo:      returnTo,
		Expires:       int(time.Now().Add(loginStateExpiresAfter).Unix()),
	})

	return h.OAuth2Config.AuthCodeURL(state, opts...)
}

func (h *Handler) getIDTokenVerifier() *jwt.IDTokenVerifier {
	return &jwt.IDTokenVerifier{
		Provider: h.Provider,
		ClientID: h.OAuth2Config.ClientID,
	}
}

type contextData struct {
	token    *oauth2.Token
	idclaims *jwt.IDClaims
}

// IDClaimsFromContext returns the validated OIDC ID Claims from the given
// request context.
func IDClaimsFromContext(ctx context.Context) (*jwt.IDClaims, bool) {
	cd, ok := ctx.Value(tokenContextKey{}).(contextData)
	if !ok {
		return nil, false
	}

	return cd.idclaims, true
}

// OAuth2TokenFromContext returns the oauth2 token from the given request
// context.
func OAuth2TokenFromContext(ctx context.Context) (*oauth2.Token, bool) {
	cd, ok := ctx.Value(tokenContextKey{}).(contextData)
	if !ok {
		return nil, false
	}

	return cd.token, true
}
