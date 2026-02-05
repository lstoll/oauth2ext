package middleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
)

const loginStateExpiresAfter = 5 * time.Minute

// DefaultKeyRefreshIterval is the default interval we try and refresh signing
// keys from the issuer.
const DefaultKeyRefreshIterval = 1 * time.Hour

var baseLogAttr = slog.String("component", "oidc-middleware")

func errAttr(err error) slog.Attr { return slog.String("err", err.Error()) }

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

// IDSSOHandler wraps another http.Handler, protecting it with web-based OIDC ID
// SSO. The handler is for a single client ID. IDClaims is the type of decoded
// ID token claims (e.g. *claims.VerifiedID).
type IDSSOHandler[IDClaims claims.Claimable] struct {
	Verifier *claims.Verifier[IDClaims]
	// Validator validates ID tokens for this handler's client ID. Required.
	Validator claims.Validator[IDClaims]
	// Provider is used for PKCE (CodeChallengeMethodsSupported). Set by
	// NewIDSSOHandlerFromDiscovery when using discovery.
	Provider *provider.Provider
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

// NewIDSSOHandlerFromDiscovery constructs a handler by discovering the
// configuration from the issuer. If sessStore is nil, cookies will be used.
// The handler can be customized after calling this.
func NewIDSSOHandlerFromDiscovery(ctx context.Context, sessStore SessionStore, issuer, clientID, clientSecret, redirectURL string) (*IDSSOHandler[*claims.VerifiedID], error) {
	prov, err := provider.DiscoverOIDCProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering provider: %w", err)
	}

	verifier, err := claims.NewVerifier[*claims.VerifiedID](prov)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	if sessStore == nil {
		sessStore = &Cookiestore{}
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     prov.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
		RedirectURL:  redirectURL,
	}
	h := &IDSSOHandler[*claims.VerifiedID]{
		Verifier:     verifier,
		Validator:    claims.NewIDTokenValidator(&claims.IDTokenValidatorOpts{ClientID: &cfg.ClientID}),
		Provider:     prov,
		OAuth2Config: cfg,
		SessionStore: sessStore,
	}
	return h, nil
}

// NewFromDiscovery is an alias for NewIDSSOHandlerFromDiscovery for backward
// compatibility. It returns a handler configured for standard OIDC ID claims
// (*claims.VerifiedID).
func NewFromDiscovery(ctx context.Context, sessStore SessionStore, issuer, clientID, clientSecret, redirectURL string) (*IDSSOHandler[*claims.VerifiedID], error) {
	return NewIDSSOHandlerFromDiscovery(ctx, sessStore, issuer, clientID, clientSecret, redirectURL)
}

// Wrap returns an http.Handler that wraps the given http.Handler and
// provides OIDC authentication.
func (h *IDSSOHandler[IDClaims]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.SessionStore == nil {
			slog.ErrorContext(r.Context(), "Uninitialized session store", baseLogAttr)
			http.Error(w, "Uninitialized session store", http.StatusInternalServerError)
			return
		}
		if h.Validator == nil {
			slog.ErrorContext(r.Context(), "Uninitialized validator", baseLogAttr)
			http.Error(w, "Uninitialized validator", http.StatusInternalServerError)
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

			// Authentication successful. Key by this handler instance so only
			// this handler can retrieve the claims.
			r = r.WithContext(context.WithValue(r.Context(), h, contextData{
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
		redirectURL, err := h.startAuthentication(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	})
}

// authenticateExisting returns (token, idClaims, nil) if the user is
// authenticated, (nil, nil, error) if a fatal error occurs, or (nil, nil, nil)
// if the user is not authenticated but no fatal error occurred.
//
// This function may modify the session if a token is refreshed, so it must be
// saved afterward.
func (h *IDSSOHandler[IDClaims]) authenticateExisting(r *http.Request, session *SessionData) (*oauth2.Token, IDClaims) {
	ctx := r.Context()

	if session.Token == nil {
		var zero IDClaims
		return nil, zero
	}

	o2cfg, err := h.getOAuth2Config()
	if err != nil {
		var zero IDClaims
		return nil, zero
	}

	// We always verify, as in the cookie store case the integrity of the data
	// is not trusted.
	idClaims, err := h.Verifier.VerifyAndDecodeToken(ctx, *session.Token.Token, h.Validator)
	if err != nil {
		// Attempt to refresh the token
		if session.Token.RefreshToken == "" {
			var zero IDClaims
			return nil, zero
		}
		token, err := o2cfg.TokenSource(ctx, session.Token.Token).Token()
		if err != nil {
			var zero IDClaims
			return nil, zero
		}
		session.Token = &oidc.TokenWithID{Token: token}
		idClaims, err = h.Verifier.VerifyAndDecodeToken(ctx, *token, h.Validator)
		if err != nil {
			var zero IDClaims
			return nil, zero
		}
	}

	// Create a new token with refresh token stripped. We ultimately don't want
	// downstream consumers refreshing themselves, as it will likely invalidate
	// ours. This should mainly be used during a HTTP request lifecycle too, so
	// we would have done the job of refreshing if needed.
	retTok := *session.Token.Token
	retTok.RefreshToken = ""
	return &retTok, idClaims
}

// authenticateCallback returns (returnTo, nil) if the user is authenticated,
// ("", error) if a fatal error occurs, or ("", nil) if the user is not
// authenticated but a fatal error did not occur.
//
// This function may modify the session if a token is authenticated, so it must be
// saved afterward.
func (h *IDSSOHandler[IDClaims]) authenticateCallback(r *http.Request, session *SessionData) (string, error) {
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
	if h.Provider != nil && slices.Contains(h.Provider.CodeChallengeMethodsSupported(), provider.CodeChallengeMethodS256) {
		opts = append(opts, oauth2.VerifierOption(foundLogin.PKCEChallenge))
	}

	o2cfg, err := h.getOAuth2Config()
	if err != nil {
		return "", err
	}
	token, err := o2cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return "", err
	}

	if _, err := h.Verifier.VerifyAndDecodeToken(ctx, *token, h.Validator); err != nil {
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

func (h *IDSSOHandler[IDClaims]) startAuthentication(r *http.Request, session *SessionData) (string, error) {
	session.Token = nil

	var (
		state         = rand.Text()
		pkceChallenge string
		returnTo      string
	)

	opts := h.AuthCodeOptions
	if h.Provider != nil && slices.Contains(h.Provider.CodeChallengeMethodsSupported(), provider.CodeChallengeMethodS256) {
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

	o2cfg, err := h.getOAuth2Config()
	if err != nil {
		return "", err
	}
	return o2cfg.AuthCodeURL(state, opts...), nil
}

func (h *IDSSOHandler[IDClaims]) getOAuth2Config() (oauth2.Config, error) {
	if h.OAuth2Config == nil {
		return oauth2.Config{}, fmt.Errorf("no OAuth2Config provided")
	}
	return *h.OAuth2Config, nil
}

type contextData struct {
	token    *oauth2.Token
	idclaims interface{}
}

// IDClaimsFromContext returns the validated OIDC ID claims from the given
// request context only if they were set by this handler instance.
func (h *IDSSOHandler[IDClaims]) IDClaimsFromContext(ctx context.Context) (IDClaims, bool) {
	cd, ok := ctx.Value(h).(contextData)
	if !ok {
		var zero IDClaims
		return zero, false
	}
	idclaims, ok := cd.idclaims.(IDClaims)
	return idclaims, ok
}
