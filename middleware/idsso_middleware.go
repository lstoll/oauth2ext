package middleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/claims"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
)

const loginStateExpiresAfter = 5 * time.Minute

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
type IDSSOHandler[IDClaims any] struct {
	// Verifier validates ID tokens and projects application claims. Required.
	Verifier claims.IDTokenResponseVerifier[IDClaims]
	// Provider is used for PKCE (CodeChallengeMethodsSupported). Set by
	// NewIDSSOHandlerFromDiscovery when using discovery.
	Provider *provider.Provider
	// DisablePKCE explicitly disables PKCE for confidential clients whose
	// providers do not support S256. It must not be used for public clients,
	// which always require PKCE.
	//
	// PKCE with S256 is the default. When discovery metadata is available, the
	// handler fails closed if S256 is not advertised. For a handler constructed
	// without discovery, S256 support is assumed unless explicitly disabled.
	DisablePKCE bool
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
	// AllowUnauthenticated, if true, lets requests without a session reach the
	// wrapped handler without ID claims in context. OAuth callbacks and
	// ServeLogin still run the auth code flow. Authorization remains the app's
	// responsibility.
	AllowUnauthenticated bool
	// AJAXUnauth401, if true, will return a 401 Unauthorized response for AJAX
	// requests instead of redirecting to the login page.
	AJAXUnauth401 bool
}

// NewIDSSOHandlerFromDiscovery constructs a handler by discovering the
// configuration from the issuer. If sessStore is nil, cookies will be used.
// The handler can be customized after calling this.
func NewIDSSOHandlerFromDiscovery(ctx context.Context, sessStore SessionStore, issuer, clientID, clientSecret, redirectURL string) (*IDSSOHandler[*claims.VerifiedID], error) {
	prov, err := provider.DiscoverOIDCProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering provider: %w", err)
	}

	verifier, err := claims.NewIDTokenVerifier(prov, claims.IDTokenVerifierOpts{
		ClientID: &clientID,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ID token verifier: %w", err)
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
		if h.Verifier == nil {
			slog.ErrorContext(r.Context(), "Uninitialized verifier", baseLogAttr)
			http.Error(w, "Uninitialized verifier", http.StatusInternalServerError)
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
			// A callback consumes its matching login transaction before exchanging
			// the code. Persist that removal even when the exchange or verification
			// fails, so a code/state pair cannot be retried.
			if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
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

		if h.AllowUnauthenticated {
			next.ServeHTTP(w, r)
			return
		}
		if h.AJAXUnauth401 && isAJAXRequest(r) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Not authenticated. Kick off an auth flow.
		redirectURL, err := h.prepareLogin(r, session, "")
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

// ServeLogin starts the OIDC authorization code flow and redirects to the IdP.
// returnTo must be a path on this application (for example "/dashboard" or
// "/items?id=1"). If returnTo is empty, GET requests use the current request
// path and query; other methods leave the post-login destination to BaseURL or
// "/" when the callback completes.
func (h *IDSSOHandler[IDClaims]) ServeLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	if h.SessionStore == nil {
		slog.ErrorContext(r.Context(), "Uninitialized session store", baseLogAttr)
		http.Error(w, "Uninitialized session store", http.StatusInternalServerError)
		return
	}
	if h.Verifier == nil {
		slog.ErrorContext(r.Context(), "Uninitialized verifier", baseLogAttr)
		http.Error(w, "Uninitialized verifier", http.StatusInternalServerError)
		return
	}
	session, err := h.SessionStore.GetOIDCSession(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to get session", baseLogAttr, errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectURL, err := h.prepareLogin(r, session, returnTo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// ServeLogout clears the OIDC session (tokens and in-flight login state),
// persists the updated session, and redirects the client. The returnTo
// parameter follows the same rules as ServeLogin: it must be a path on this
// application when non-empty; if empty, GET requests use the current request
// path and query; other methods redirect to BaseURL or "/" after logout.
func (h *IDSSOHandler[IDClaims]) ServeLogout(w http.ResponseWriter, r *http.Request, returnTo string) {
	if h.SessionStore == nil {
		slog.ErrorContext(r.Context(), "Uninitialized session store", baseLogAttr)
		http.Error(w, "Uninitialized session store", http.StatusInternalServerError)
		return
	}
	if h.Verifier == nil {
		slog.ErrorContext(r.Context(), "Uninitialized verifier", baseLogAttr)
		http.Error(w, "Uninitialized verifier", http.StatusInternalServerError)
		return
	}
	session, err := h.SessionStore.GetOIDCSession(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to get session", baseLogAttr, errAttr(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Token = nil
	session.Logins = nil
	if err := h.SessionStore.SaveOIDCSession(w, r, session); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, resolveReturnTo(returnToFromRequest(r, returnTo), h.BaseURL), http.StatusSeeOther)
}

// authenticateExisting returns (token, idClaims, nil) if the user is
// authenticated, (nil, nil, error) if a fatal error occurs, or (nil, nil, nil)
// if the user is not authenticated but no fatal error occurred.
//
// This function may modify the session if a token is refreshed, so it must be
// saved afterward.
func (h *IDSSOHandler[IDClaims]) authenticateExisting(r *http.Request, session *SessionData) (*oauth2.Token, IDClaims) {
	ctx := r.Context()

	if session.Token == nil || session.Token.Token == nil {
		var zero IDClaims
		return nil, zero
	}

	o2cfg, err := h.getOAuth2Config()
	if err != nil {
		var zero IDClaims
		return nil, zero
	}

	// Refresh based on OAuth token validity, not as recovery from an ID-token or
	// application-claims verification failure. Cookie sessions intentionally
	// contain only an ID token, so an absent access token is verified directly.
	if session.Token.AccessToken != "" && !session.Token.Valid() {
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
	}

	// Always verify the ID token because cookie-backed session contents are not
	// trusted and server-side stores may also contain stale or corrupted data.
	idClaims, err := h.Verifier.VerifyTokenResponse(ctx, session.Token.Token, claims.IDTokenValidationInput{
		IgnoreNonce: true,
	})
	if err != nil {
		var zero IDClaims
		return nil, zero
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

	var foundLogin SessionDataLogin
	found := false
	for i, sl := range session.Logins {
		if sl.State != state {
			continue
		}
		// Consume a matching transaction before using its authorization code.
		// This also removes expired state from SessionStores that do not enforce
		// SessionDataLogin.Expires themselves.
		session.Logins = append(session.Logins[:i], session.Logins[i+1:]...)
		foundLogin = sl
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("state did not match")
	}
	if !time.Now().Before(time.Unix(int64(foundLogin.Expires), 0)) {
		return "", fmt.Errorf("login state expired")
	}

	opts := h.AuthCodeOptions
	pkceEnabled, err := h.pkceEnabled()
	if err != nil {
		return "", err
	}
	if pkceEnabled && foundLogin.PKCEChallenge == "" {
		return "", fmt.Errorf("login state is missing the required PKCE verifier")
	}
	if foundLogin.PKCEChallenge != "" {
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

	if _, err := h.Verifier.VerifyTokenResponse(ctx, token, claims.IDTokenValidationInput{
		ExpectedNonce:     &foundLogin.Nonce,
		AuthorizationCode: &code,
	}); err != nil {
		return "", fmt.Errorf("verifying id_token failed: %w", err)
	}

	session.Token = &oidc.TokenWithID{Token: token}

	returnTo := resolveReturnTo(foundLogin.ReturnTo, h.BaseURL)

	return returnTo, nil
}

// returnToFromRequest resolves the in-app redirect target stored for the OAuth
// callback. If the result is empty, authenticateCallback and ServeLogout apply
// BaseURL or "/".
func returnToFromRequest(r *http.Request, explicitReturnTo string) string {
	switch {
	case explicitReturnTo != "":
		return sanitizeReturnTo(explicitReturnTo)
	case r.Method == http.MethodGet:
		return sanitizeReturnTo(r.URL.RequestURI())
	default:
		return ""
	}
}

func (h *IDSSOHandler[IDClaims]) prepareLogin(r *http.Request, session *SessionData, explicitReturnTo string) (string, error) {
	session.Token = nil

	var (
		state         = rand.Text()
		nonce         = rand.Text()
		pkceChallenge string
	)
	returnTo := returnToFromRequest(r, explicitReturnTo)

	opts := append(slices.Clone(h.AuthCodeOptions), oauth2.SetAuthURLParam("nonce", nonce))
	pkceEnabled, err := h.pkceEnabled()
	if err != nil {
		return "", err
	}
	if pkceEnabled {
		pkceChallenge = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(pkceChallenge))
	}

	session.Logins = append(session.Logins, SessionDataLogin{
		State:         state,
		Nonce:         nonce,
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

func (h *IDSSOHandler[IDClaims]) pkceEnabled() (bool, error) {
	publicClient := h.OAuth2Config != nil && h.OAuth2Config.ClientSecret == ""
	if h.DisablePKCE {
		if publicClient {
			return false, fmt.Errorf("PKCE cannot be disabled for a public client")
		}
		return false, nil
	}
	if h.Provider == nil {
		return true, nil
	}
	if slices.Contains(h.Provider.CodeChallengeMethodsSupported(), provider.CodeChallengeMethodS256) {
		return true, nil
	}
	return false, fmt.Errorf("provider does not advertise PKCE S256 support; set DisablePKCE only for a confidential client")
}

func (h *IDSSOHandler[IDClaims]) getOAuth2Config() (oauth2.Config, error) {
	if h.OAuth2Config == nil {
		return oauth2.Config{}, fmt.Errorf("no OAuth2Config provided")
	}
	return *h.OAuth2Config, nil
}

func isAJAXRequest(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

type contextData struct {
	token    *oauth2.Token
	idclaims any
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
