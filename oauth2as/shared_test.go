package oidcop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// contains helpers used by multiple tests

type stubSMGR struct {
	// sessions maps JSON session objects by their ID
	// JSON > proto here for better debug output
	sessions map[string][]byte
}

func newStubSMGR() *stubSMGR {
	return &stubSMGR{
		sessions: map[string][]byte{},
	}
}

func (s *stubSMGR) NewID() string {
	return mustGenerateID()
}

func mustGenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("can't create ID, rand.Read failed: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *stubSMGR) GetSession(_ context.Context, sessionID string, into Session) (found bool, err error) {
	sess, ok := s.sessions[sessionID]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(sess, into); err != nil {
		return false, err
	}
	return true, nil
}

func (s *stubSMGR) PutSession(_ context.Context, sess Session) error {
	if sess.ID() == "" {
		return fmt.Errorf("session has no ID")
	}
	sb, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	s.sessions[sess.ID()] = sb
	return nil
}

func (s *stubSMGR) DeleteSession(ctx context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}
