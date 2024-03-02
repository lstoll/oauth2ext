package middleware

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/lstoll/oidc/internal"
)

type memorySessionStore struct {
	// CookieTemplate is used to create the cookie we track the session ID in.
	// It must have at least the name set.
	CookieTemplate http.Cookie

	sessions   map[string]SessionData
	sessionsMu sync.Mutex
}

// NewMemorySessionStore creates a simple session store, that tracks state in
// memory. It is mainly used for testing, it is not suitable for anything
// outside a single process as the state will not be shared. It also does not
// have robust cleaning of stored session data.
//
// It is provided with a "template" http.Cookie - this will be used for the
// cookies the session ID is tracked with. It must have at least a name set.
func NewMemorySessionStore(template http.Cookie) (SessionStore, error) {
	if template.Name == "" {
		return nil, fmt.Errorf("template must have a name")
	}
	return &memorySessionStore{
		CookieTemplate: template,
		sessions:       make(map[string]SessionData),
	}, nil
}

func (m *memorySessionStore) Get(r *http.Request) (*SessionData, error) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

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

func (m *memorySessionStore) Save(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

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

	nc := m.CookieTemplate

	nc.Value = sid
	m.sessions[sid] = *d

	http.SetCookie(w, &nc)

	return nil
}

func (m *memorySessionStore) sidFromCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(m.CookieTemplate.Name)
	if err != nil && err != http.ErrNoCookie {
		return "", fmt.Errorf("failed getting cookie: %w", err)
	}
	if c != nil {
		return c.Value, nil
	}
	return "", nil
}
