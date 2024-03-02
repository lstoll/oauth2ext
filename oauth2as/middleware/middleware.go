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
	"github.com/lstoll/oidc/discovery"
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
	// IDToken is the id_token for the current logged in user
	IDToken string `json:"oidc_id_token,omitempty"`
	// RefreshToken is the refresh token for this OIDC session. It is only
	// persisted if a secure session store is used.
	RefreshToken string `json:"oidc_refresh_token,omitempty"`
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

	discoveryClient *discovery.Client
	oidcClient      *oidc.Client
	lastKeyRefresh  time.Time
	oidcClientMu    sync.Mutex
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
		tok, err := h.authenticateExisting(r, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if tok != nil {
			if err := h.SessionStore.Save(w, r, session); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Authentication successful
			r = r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, tok))
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
func (h *Handler) authenticateExisting(r *http.Request, session *SessionData) (*oidc.Token, error) {
	ctx := r.Context()

	if session.IDToken == "" {
		return nil, nil
	}

	oidccl, err := h.getOIDCClient(ctx)
	if err != nil {
		return nil, err
	}

	idToken, err := oidccl.VerifyRaw(ctx, h.ClientID, session.IDToken)
	if err != nil {
		// Attempt to refresh the token
		if session.RefreshToken == "" {
			return nil, nil
		}

		oidccl, err := h.getOIDCClient(ctx)
		if err != nil {
			return nil, err
		}

		token, err := oidccl.TokenSource(ctx, &oidc.Token{RefreshToken: session.RefreshToken}).Token(ctx)
		if err != nil {
			return nil, nil
		}

		session.IDToken = token.IDToken
		session.RefreshToken = token.RefreshToken

		idToken = &token.Claims
	}

	// create a new token with refresh token stripped. We ultimtely don't want
	// downstream consumers refreshing themselves, as it will likely invalidate
	// ours. This should mainly be used during a HTTP request lifecycle too, so
	// we would have done the job of refreshing if needed.
	return &oidc.Token{IDToken: session.IDToken, Claims: *idToken, Expiry: idToken.Expiry.Time()}, nil
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

	oidccl, err := h.getOIDCClient(ctx)
	if err != nil {
		return "", err
	}

	h.oidcClientMu.Lock()
	defer h.oidcClientMu.Unlock()

	// do a refresh before we validate, if we need to.
	if time.Now().After(h.lastKeyRefresh.Add(h.KeyRefreshInterval)) {
		if err := h.discoveryClient.RefreshJWKS(r.Context()); err != nil {
			return "", fmt.Errorf("refreshing JWKS: %w", err)
		}
	}

	token, err := oidccl.Exchange(ctx, code, oidc.ExchangeWithPKCE(session.PKCEChallenge))
	if err != nil {
		return "", err
	}

	session.IDToken = token.IDToken
	session.RefreshToken = token.RefreshToken
	session.State = ""

	returnTo := session.ReturnTo
	if returnTo == "" {
		returnTo = h.BaseURL
	}
	session.ReturnTo = ""

	return returnTo, nil
}

func (h *Handler) startAuthentication(r *http.Request, session *SessionData) (string, error) {
	oidccl, err := h.getOIDCClient(r.Context())
	if err != nil {
		return "", err
	}

	session.IDToken = ""
	session.RefreshToken = ""

	session.State = randomState()

	session.ReturnTo = ""
	if r.Method == http.MethodGet {
		session.ReturnTo = r.URL.RequestURI()
	}

	return oidccl.AuthCodeURL(session.State, oidc.AuthCodeWithPKCE(&session.PKCEChallenge)), nil
}

func (h *Handler) getOIDCClient(ctx context.Context) (*oidc.Client, error) {
	h.oidcClientMu.Lock()
	defer h.oidcClientMu.Unlock()
	if h.oidcClient != nil {
		return h.oidcClient, nil
	}

	var opts []oidc.ClientOpt
	if len(h.ACRValues) > 0 {
		opts = append(opts, oidc.WithACRValues(h.ACRValues, true))
	}
	if len(h.AdditionalScopes) > 0 {
		opts = append(opts, oidc.WithAdditionalScopes(h.AdditionalScopes))
	}
	var err error
	h.discoveryClient, err = discovery.NewClient(ctx, h.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering issuer %s: %w", h.Issuer, err)
	}
	h.oidcClient, err = oidc.NewClient(h.discoveryClient.Metadata(), h.discoveryClient.PublicHandle, h.ClientID, h.ClientSecret, h.RedirectURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC client: %w", err)
	}

	h.lastKeyRefresh = time.Now()

	if h.KeyRefreshInterval == 0 {
		h.KeyRefreshInterval = DefaultKeyRefreshIterval
	}

	return h.oidcClient, nil
}

// ClaimsFromContext returns the claims for the given request context
func ClaimsFromContext(ctx context.Context) *oidc.Claims {
	tok, ok := ctx.Value(tokenContextKey{}).(*oidc.Token)
	if !ok {
		return nil
	}

	return &tok.Claims
}

// RawIDTokenFromContext returns the raw JWT from the given request context
func RawIDTokenFromContext(ctx context.Context) string {
	tok, ok := ctx.Value(tokenContextKey{}).(*oidc.Token)
	if !ok {
		return ""
	}

	return tok.IDToken
}

var _ oidc.TokenSource = (*contextTokenSource)(nil)

type contextTokenSource struct {
	tok *oidc.Token
}

func (c *contextTokenSource) Token(ctx context.Context) (*oidc.Token, error) {
	if c == nil || c.tok == nil {
		return nil, fmt.Errorf("no token in context")
	}
	return c.tok, nil
}

// TokenSourceFromContext returns a usable tokensource from this request context. The request
// must have been wrapped with the middleware for this to be initialized. This token source is
func TokenSourceFromContext(ctx context.Context) oidc.TokenSource {
	tok, ok := ctx.Value(tokenContextKey{}).(*oidc.Token)
	if !ok {
		return &contextTokenSource{}
	}

	return &contextTokenSource{tok: tok}
}

func randomState() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}

	return base64.RawStdEncoding.EncodeToString(b)
}
