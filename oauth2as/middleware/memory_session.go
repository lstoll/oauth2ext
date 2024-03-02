package middleware

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/lstoll/oidc/internal"
)

// MemorySessionStore is a simple session store, that tracks state in memory. It
// is mainly used for testing, it is not suitible for anything outside a single
// process.
type MemorySessionStore struct {
	// CookieTemplate is used to create the cookie we track the session ID in.
	// It must have at least the name set.
	CookieTemplate *http.Cookie

	sessions   map[string]SessionData
	sessionsMu sync.Mutex
}

func (m *MemorySessionStore) Get(r *http.Request) (*SessionData, error) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	if err := m.init(); err != nil {
		return nil, err
	}

	sid, err := m.sidFromCookie(r)
	if err != nil {
		return nil, err
	}

	var sd *SessionData
	if sid != "" {
		s, ok := m.sessions[sid]
		if ok {
			sd = &s
		}
	}
	if sd == nil {
		sd = new(SessionData)
	}

	return sd, nil
}

func (m *MemorySessionStore) Save(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	if err := m.init(); err != nil {
		return err
	}

	if d == nil {
		http.SetCookie(w, &http.Cookie{
			Name:   m.CookieTemplate.Name,
			Value:  "",
			MaxAge: -1,
		})
		sid, _ := m.sidFromCookie(r)
		if sid != "" {
			delete(m.sessions, sid)
		}
		return nil
	}

	sid := internal.MustUUIDv4()

	nc := &http.Cookie{}
	*nc = *m.CookieTemplate

	nc.Value = sid
	m.sessions[sid] = *d

	http.SetCookie(w, nc)

	return nil
}

func (m *MemorySessionStore) init() error {
	if m.sessions == nil {
		m.sessions = make(map[string]SessionData)
	}
	if m.CookieTemplate == nil || m.CookieTemplate.Name == "" {
		return fmt.Errorf("cookie template missing name")
	}
	return nil
}

func (m *MemorySessionStore) sidFromCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(m.CookieTemplate.Name)
	if err != nil && err != http.ErrNoCookie {
		return "", fmt.Errorf("failed getting cookie: %w", err)
	}
	if c != nil {
		return c.Value, nil
	}
	return "", nil
}
