package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/oidc"
)

const DefaultMaxActiveLoginStates = 5

type CookieOpts struct {
	TokenCookieName        string
	LoginStateCookiePrefix string // Prefix for cookies storing individual login states
	Path                   string
	Secure                 bool
	SameSite               http.SameSite
	// Persist is used to control if the token cookie is persisted across
	// browser sessions. If true, the cookie expiration will be set based on the
	// token lifetime. If false, the cookie will be set to expire when the
	// browser is closed.
	Persist bool
}

var DefaultCookieOpts = CookieOpts{
	TokenCookieName:        "__HOST-auth",
	LoginStateCookiePrefix: "__HOST-lstate-", // Note the trailing hyphen for separation
	Path:                   "/",
	Secure:                 true,
	SameSite:               http.SameSiteLaxMode,
}

// Cookiestore is a basic implementation of the middleware's session store, that
// stores values in a series of cookies. These are not signed or encrypted, so
// only the ID token is tracked - the access token and refresh tokens are
// discarded, to avoid risk of them leaking. The login state is also stored
// unauthenticated, applications should take this in to mind. Cookie storage is
// limited, so too many in-flight logins may cause issues.
//
// This provides a simple default, but it is generally recommended to use a
// server-side session store.
type Cookiestore struct {
	// CookieOpts is used to create the cookie we track the session ID in. If
	// not set, DefaultCookieOpts will be used.
	CookieOpts           *CookieOpts
	MaxActiveLoginStates int
}

func (c *Cookiestore) GetOIDCSession(r *http.Request) (*SessionData, error) {
	sd := &SessionData{}
	opts := c.getCookieOpts()

	idtc, err := r.Cookie(opts.TokenCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return nil, fmt.Errorf("getting token cookie %q: %w", opts.TokenCookieName, err)
	} else if err == nil {
		// got a token cookie, load it
		o2t := new(oauth2.Token)
		o2t = oidc.AddIDToken(o2t, idtc.Value)
		sd.Token = &oidc.TokenWithID{
			Token: o2t,
		}
	}

	// Reconstruct login states from individual cookies
	for _, cookie := range r.Cookies() {
		if after, ok := strings.CutPrefix(cookie.Name, opts.LoginStateCookiePrefix); ok {
			state := after
			if state == "" {
				continue // Should not happen with a proper prefix
			}

			v, err := url.ParseQuery(cookie.Value)
			if err != nil {
				// Malformed cookie value, skip
				continue
			}

			expiresStr := v.Get("ex")
			if expiresStr == "" {
				// Expires is mandatory, skip
				continue
			}
			expires, err := strconv.ParseInt(expiresStr, 10, 64)
			if err != nil {
				// Malformed expires, skip
				continue
			}

			if time.Now().Unix() > expires {
				// Expired entry, skip (and ideally, should be cleaned up by SaveOIDCSession on next write)
				continue
			}

			sd.Logins = append(sd.Logins, SessionDataLogin{
				State:         state,
				PKCEChallenge: v.Get("pc"), // pkce_challenge
				ReturnTo:      v.Get("rt"), // return_to
				Expires:       int(expires),
			})
		}
	}

	return sd, nil
}

type expiresClaim struct {
	Expiry int `json:"exp,omitempty"`
}

func (c *expiresClaim) Time() time.Time {
	return time.Unix(int64(c.Expiry), 0)
}

func (c *Cookiestore) SaveOIDCSession(w http.ResponseWriter, r *http.Request, d *SessionData) error {

	// Save or delete the main token cookie
	if d.Token != nil {
		var cl expiresClaim
		idt, ok := oidc.GetIDToken(d.Token.Token)
		if !ok {
			return fmt.Errorf("token contains no ID token")
		}
		if err := internal.InsecureExtractJWTPayload(idt, &cl); err != nil {
			return fmt.Errorf("extracting id token claims: %w", err)
		}
		if err := setCookieIfNotSet(w, r, c.newTokenCookie(idt, cl.Time())); err != nil {
			return fmt.Errorf("saving token cookie: %w", err)
		}
	} else {
		if err := setCookieIfNotSet(w, r, c.newTokenCookie("", time.Time{})); err != nil {
			return fmt.Errorf("deleting token cookie: %w", err)
		}
	}

	// Manage individual login state cookies
	activeLoginStates := map[string]SessionDataLogin{}
	validLoginsForCookie := []SessionDataLogin{}

	for _, l := range d.Logins {
		if time.Now().Unix() > int64(l.Expires) {
			continue // Skip expired logins
		}
		validLoginsForCookie = append(validLoginsForCookie, l)
	}

	// Sort by expiration descending (newest/furthest expiry first)
	sort.Slice(validLoginsForCookie, func(i, j int) bool {
		return validLoginsForCookie[i].Expires > validLoginsForCookie[j].Expires
	})

	maxStates := c.MaxActiveLoginStates
	if maxStates <= 0 {
		maxStates = DefaultMaxActiveLoginStates
	}
	if len(validLoginsForCookie) > maxStates {
		validLoginsForCookie = validLoginsForCookie[:maxStates]
	}

	for _, l := range validLoginsForCookie {
		activeLoginStates[l.State] = l
	}

	// Iterate through existing cookies to update or delete
	for _, cookie := range r.Cookies() {
		if after, ok := strings.CutPrefix(cookie.Name, c.getCookieOpts().LoginStateCookiePrefix); ok {
			state := after
			if _, isActive := activeLoginStates[state]; !isActive {
				// This state is no longer active or was truncated, delete its cookie
				_ = setCookieIfNotSet(w, r, c.newLoginStateCookie(state, "", "", 0))
			}
		}
	}

	// Set cookies for all currently active (and potentially new) login states
	for state, loginData := range activeLoginStates {
		cookie := c.newLoginStateCookie(state, loginData.PKCEChallenge, loginData.ReturnTo, loginData.Expires)
		_ = setCookieIfNotSet(w, r, cookie)
	}

	return nil
}

func (c *Cookiestore) newTokenCookie(value string, expires time.Time) *http.Cookie {
	ct := c.getCookieOpts()
	nc := &http.Cookie{
		Name:     ct.TokenCookieName,
		Path:     ct.Path,
		Secure:   ct.Secure,
		SameSite: ct.SameSite,
		Value:    value,
		HttpOnly: true,
	}
	if value == "" {
		nc.MaxAge = -1
		return nc
	}
	if ct.Persist {
		// use max age, the server clock is hopefully more accurate than the
		// client clock.
		nc.MaxAge = int(time.Until(expires).Seconds())
	}
	return nc
}

// newLoginStateCookie creates a cookie for an individual login state.
// The expiration of the cookie is tied to the login state's expiration.
func (c *Cookiestore) newLoginStateCookie(state, pkceChallenge, returnTo string, expires int) *http.Cookie {
	opts := c.getCookieOpts()
	v := url.Values{}
	v.Set("ex", strconv.FormatInt(int64(expires), 10))
	if pkceChallenge != "" {
		v.Set("pc", pkceChallenge)
	}
	if returnTo != "" {
		v.Set("rt", returnTo)
	}

	expireTime := time.Unix(int64(expires), 0)

	nc := &http.Cookie{
		Name:     opts.LoginStateCookiePrefix + state,
		Value:    v.Encode(),
		Path:     opts.Path,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
		HttpOnly: true,
	}

	// Set expires/max-age. Login state cookies are not persisted via opts.Persist,
	// their lifetime is strictly tied to their own 'expires' field.
	if time.Now().After(expireTime) {
		nc.MaxAge = -1 // Expired, delete
	}
	return nc
}

func (c *Cookiestore) getCookieOpts() *CookieOpts {
	if c.CookieOpts != nil {
		return c.CookieOpts
	}
	return &DefaultCookieOpts
}

func setCookieIfNotSet(w http.ResponseWriter, r *http.Request, c *http.Cookie) error {
	ec, err := r.Cookie(c.Name)
	if errors.Is(err, http.ErrNoCookie) {
		if c.Value != "" {
			http.SetCookie(w, c)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("getting cookie: %w", err)
	}
	if ec.Value != c.Value {
		http.SetCookie(w, c)
	}
	return nil
}
