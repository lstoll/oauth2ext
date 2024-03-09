package middleware

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lstoll/oidc"
	"golang.org/x/oauth2"
)

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
	// State for an in-progress auth flow.
	State string `json:"oidc_state,omitempty"`
	// PKCEChallenge for the in-progress auth flow
	PKCEChallenge string `json:"pkce_challenge,omitempty"`
	// ReturnTo is where we should navigate to at the end of the flow
	ReturnTo string `json:"oidc_return_to,omitempty"`
	// Token stores the returned oauth2.Token
	Token *oidc.MarshaledToken `json:"token,omitempty"`
}

// SessionStore are used for managing state across requests.
type SessionStore interface {
	// Get should always return a valid, usable session. If the session does not
	// exist, it should be empty. error indicates that there was a failure that
	// we should not proceed from.
	Get(*http.Request) (*SessionData, error)
	// Save should store the updated session. If the session data is nil, the
	// session should be deleted.
	Save(http.ResponseWriter, *http.Request, *SessionData) error
}

// Handler wraps another http.Handler, protecting it with OIDC authentication.
type Handler struct {
	// Issuer is the URL to the OIDC issuer
	Issuer string
	// KeyRefreshInterval is how often we should try and refresh the signing keys
	// from the issuer. Defaults to DefaultKeyRefreshIterval
	KeyRefreshInterval time.Duration
	// ClientID is a client ID for the relying party (the service authenticating
	// against the OIDC server)
	ClientID string
	// ClientSecret is a client secret for the relying party
	ClientSecret string
	// BaseURL is the base URL for this relying party. If it is not safe to
	// redirect the user to their original destination, they will be redirected
	// to this URL.
	BaseURL string
	// RedirectURL is the callback URL registered with the OIDC issuer for this
	// relying party
	RedirectURL string
	// AdditionalScopes is a list of scopes to request from the OIDC server, in
	// addition to the base oidc scope.
	AdditionalScopes []string
	// ACRValues to request from the remote server. The handler validates that
	// the returned token contains one of these.
	ACRValues []string

	// SessionStore are used for managing state that we need to persist across
	// requests. It needs to be able to store ID and refresh tokens, plus a
	// small amount of additional data. Required.
	SessionStore SessionStore

	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	oidcClientMu sync.Mutex
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
		session, err := h.SessionStore.Get(r)
		if err != nil {
			slog.ErrorContext(r.Context(), "Failed to get session", baseLogAttr, errAttr(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Check for a user that's already authenticated
		tok, claims, err := h.authenticateExisting(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if tok != nil {
			if err := h.SessionStore.Save(w, r, session); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Authentication successful
			r = r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, contextData{
				token:  tok,
				claims: claims,
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
			if err := h.SessionStore.Save(w, r, session); err != nil {
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

		if err := h.SessionStore.Save(w, r, session); err != nil {
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
func (h *Handler) authenticateExisting(r *http.Request, session *SessionData) (*oauth2.Token, *oidc.Claims, error) {
	ctx := r.Context()

	if session.Token == nil {
		return nil, nil, nil
	}

	provider, oauth2cfg, err := h.getOIDCClient(r.Context())
	if err != nil {
		return nil, nil, err
	}

	// TODO(lstoll) is it really worth verifying every time, if we obtained it
	// and stored it in the session? Can probably just check expiry.
	claims, err := provider.VerifyIDToken(ctx, session.Token.Token, h.verificationOptions())
	if err != nil {
		// Attempt to refresh the token
		if session.Token.RefreshToken == "" {
			return nil, nil, nil
		}
		token, err := oauth2cfg.TokenSource(ctx, session.Token.Token).Token()
		if err != nil {
			return nil, nil, nil
		}
		// TODO(lstoll) same with over-verification
		_, err = provider.VerifyIDToken(ctx, token, h.verificationOptions())
		if err != nil {
			return nil, nil, nil
		}
	}

	// create a new token with refresh token stripped. We ultimtely don't want
	// downstream consumers refreshing themselves, as it will likely invalidate
	// ours. This should mainly be used during a HTTP request lifecycle too, so
	// we would have done the job of refreshing if needed.
	retTok := *session.Token.Token
	retTok.RefreshToken = ""
	return &retTok, claims, nil
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

	if session.State == "" || session.State != state {
		return "", fmt.Errorf("state did not match")
	}

	provider, oauth2cfg, err := h.getOIDCClient(r.Context())
	if err != nil {
		return "", err
	}

	token, err := oauth2cfg.Exchange(ctx, code, oauth2.VerifierOption(session.PKCEChallenge))
	if err != nil {
		return "", err
	}

	// TODO(lstoll) do we want to verify the ID token here? was retrieved from a
	// trusted source....
	_, err = provider.VerifyIDToken(ctx, token, h.verificationOptions())
	if err != nil {
		return "", fmt.Errorf("verifying id_token failed: %w", err)
	}

	session.Token = &oidc.MarshaledToken{Token: token}
	session.State = ""

	returnTo := session.ReturnTo
	if returnTo == "" {
		returnTo = h.BaseURL
	}
	session.ReturnTo = ""

	return returnTo, nil
}

func (h *Handler) startAuthentication(r *http.Request, session *SessionData) (string, error) {
	_, oauth2cfg, err := h.getOIDCClient(r.Context())
	if err != nil {
		return "", err
	}

	session.Token = nil

	session.State = randomState()
	session.PKCEChallenge = oauth2.GenerateVerifier()

	session.ReturnTo = ""
	if r.Method == http.MethodGet {
		session.ReturnTo = r.URL.RequestURI()
	}

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(session.PKCEChallenge)}
	if len(h.ACRValues) > 0 {
		opts = append(opts, oidc.SetACRValues(h.ACRValues))
	}

	return oauth2cfg.AuthCodeURL(session.State, opts...), nil
}

func (h *Handler) getOIDCClient(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	h.oidcClientMu.Lock()
	defer h.oidcClientMu.Unlock()
	if h.provider != nil {
		return h.provider, h.oauth2Config, nil
	}

	var err error
	h.provider, err = oidc.DiscoverProvider(ctx, h.Issuer, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("discovering issuer %s: %w", h.Issuer, err)
	}
	h.oauth2Config = &oauth2.Config{
		ClientID:     h.ClientID,
		ClientSecret: h.ClientSecret,
		RedirectURL:  h.RedirectURL,
		Scopes:       append([]string{"openid"}, h.AdditionalScopes...),
		Endpoint:     h.provider.Endpoint(),
	}

	return h.provider, h.oauth2Config, nil
}

func (h *Handler) verificationOptions() oidc.VerificationOpts {
	return oidc.VerificationOpts{
		ClientID:  h.ClientID,
		ACRValues: h.ACRValues,
	}
}

type contextData struct {
	token  *oauth2.Token
	claims *oidc.Claims
}

// ClaimsFromContext returns the claims for the given request context
func ClaimsFromContext(ctx context.Context) *oidc.Claims {
	cd, ok := ctx.Value(tokenContextKey{}).(contextData)
	if !ok {
		return nil
	}

	return cd.claims
}

// RawIDTokenFromContext returns the raw JWT from the given request context
func RawIDTokenFromContext(ctx context.Context) string {
	cd, ok := ctx.Value(tokenContextKey{}).(contextData)
	if !ok {
		return ""
	}

	idt, ok := oidc.IDToken(cd.token)
	if !ok {
		return ""
	}

	return idt
}

// TokenSourceFromContext returns a usable tokensource from this request context. The request
// must have been wrapped with the middleware for this to be initialized. This token source is
func TokenSourceFromContext(ctx context.Context) oauth2.TokenSource {
	cd, ok := ctx.Value(tokenContextKey{}).(contextData)
	if !ok {
		return nil
	}

	return oauth2.StaticTokenSource(cd.token)
}

func randomState() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}
