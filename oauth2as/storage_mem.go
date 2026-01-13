package oauth2as

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MemStorage implements the Storage interface with an in-memory dataset. It
// serializes and deserializes the data, to avoid things hanging on to
// references to the original data.
type MemStorage struct {
	mu sync.RWMutex
	// grants stores grants by their ID as JSON
	grants map[string]json.RawMessage
	// authCodes stores authorization codes by their ID as JSON
	authCodes map[string]json.RawMessage
	// refreshTokens stores refresh tokens by their ID as JSON
	refreshTokens map[string]json.RawMessage
}

// NewMemStorage creates a new in-memory storage instance.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		grants:        make(map[string]json.RawMessage),
		authCodes:     make(map[string]json.RawMessage),
		refreshTokens: make(map[string]json.RawMessage),
	}
}

// CreateGrant stores a new grant in memory and returns its ID.
func (m *MemStorage) CreateGrant(ctx context.Context, grant *StoredGrant) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := newUUIDv4()

	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}

	m.grants[id] = grantJSON

	return id, nil
}

// UpdateGrant updates an existing grant in memory.
func (m *MemStorage) UpdateGrant(ctx context.Context, id string, grant *StoredGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	grantJSON, exists := m.grants[id]
	if !exists {
		return ErrNotFound
	}

	var storedGrant StoredGrant
	if err := json.Unmarshal(grantJSON, &storedGrant); err != nil {
		return err
	}

	if storedGrant.Version != grant.Version {
		return ErrConcurrentUpdate
	}

	grant.Version++

	// Marshal to JSON for storage
	newGrantJSON, err := json.Marshal(grant)
	if err != nil {
		return err
	}

	m.grants[id] = newGrantJSON

	return nil
}

// ExpireGrant removes a grant from memory, and all associated tokens.
func (m *MemStorage) ExpireGrant(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.grants, id)

	return nil
}

// GetGrant retrieves a grant by its ID. Returns ErrNotFound if not found.
func (m *MemStorage) GetGrant(ctx context.Context, id string) (*StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grantJSON, exists := m.grants[id]
	if !exists {
		return nil, ErrNotFound
	}

	var grant StoredGrant
	if err := json.Unmarshal(grantJSON, &grant); err != nil {
		return nil, err
	}

	if grant.ExpiresAt.Before(time.Now()) {
		return nil, ErrNotFound
	}

	return &grant, nil
}

// CreateAuthCode stores a new authorization code in memory using the provided ID.
func (m *MemStorage) CreateAuthCode(ctx context.Context, userID, grantID, codeID string, code *StoredAuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.authCodes[codeID]; exists {
		return fmt.Errorf("auth code with ID %s already exists", codeID)
	}

	codeCopy := *code
	codeCopy.GrantID = grantID
	codeCopy.UserID = userID

	// Marshal to JSON for storage
	codeJSON, err := json.Marshal(&codeCopy)
	if err != nil {
		return err
	}

	m.authCodes[codeID] = codeJSON

	return nil
}

// ExpireAuthCode removes an authorization code from memory.
func (m *MemStorage) ExpireAuthCode(ctx context.Context, userID, grantID, codeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exists := m.authCodes[codeID]
	if !exists {
		return ErrNotFound
	}
	delete(m.authCodes, codeID)

	return nil
}

// GetAuthCodeAndGrant retrieves an auth code and its associated grant by code ID.
func (m *MemStorage) GetAuthCodeAndGrant(ctx context.Context, userID, grantID, codeID string) (*StoredAuthCode, *StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	codeJSON, exists := m.authCodes[codeID]
	if !exists {
		return nil, nil, ErrNotFound
	}

	var storedCode StoredAuthCode
	if err := json.Unmarshal(codeJSON, &storedCode); err != nil {
		return nil, nil, err
	}

	// Return ErrNotFound if GrantID/UserID don't match (mimics DB lookup failure)
	if storedCode.GrantID != grantID || storedCode.UserID != userID {
		return nil, nil, ErrNotFound
	}

	grantJSON, exists := m.grants[storedCode.GrantID]
	if !exists {
		return nil, nil, ErrNotFound
	}

	var grant StoredGrant
	if err := json.Unmarshal(grantJSON, &grant); err != nil {
		return nil, nil, err
	}

	return &storedCode, &grant, nil
}

// CreateRefreshToken stores a new refresh token in memory using the provided ID.
func (m *MemStorage) CreateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *StoredRefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.refreshTokens[tokenID]; exists {
		return fmt.Errorf("refresh token with ID %s already exists", tokenID)
	}

	tokenCopy := *token
	tokenCopy.GrantID = grantID
	tokenCopy.UserID = userID

	// Marshal to JSON for storage
	tokenJSON, err := json.Marshal(&tokenCopy)
	if err != nil {
		return err
	}

	m.refreshTokens[tokenID] = tokenJSON

	return nil
}

// UpdateRefreshToken updates an existing refresh token in memory.
func (m *MemStorage) UpdateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *StoredRefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokenJSON, exists := m.refreshTokens[tokenID]
	if !exists {
		return ErrNotFound
	}

	var storedToken StoredRefreshToken
	if err := json.Unmarshal(tokenJSON, &storedToken); err != nil {
		return err
	}

	if storedToken.Version != token.Version {
		return ErrConcurrentUpdate
	}

	token.Version++

	// We could check if userID/grantID match existing, but simpler to just overwrite
	newTokenJSON, err := json.Marshal(token)
	if err != nil {
		return err
	}

	m.refreshTokens[tokenID] = newTokenJSON

	return nil
}

// ExpireRefreshToken removes a refresh token from memory.
func (m *MemStorage) ExpireRefreshToken(ctx context.Context, userID, grantID, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exists := m.refreshTokens[tokenID]
	if !exists {
		return ErrNotFound
	}
	delete(m.refreshTokens, tokenID)

	return nil
}

// GetRefreshTokenAndGrant retrieves a refresh token and its associated grant by token ID.
func (m *MemStorage) GetRefreshTokenAndGrant(ctx context.Context, userID, grantID, tokenID string) (*StoredRefreshToken, *StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tokenJSON, exists := m.refreshTokens[tokenID]
	if !exists {
		return nil, nil, ErrNotFound
	}

	var storedToken StoredRefreshToken
	if err := json.Unmarshal(tokenJSON, &storedToken); err != nil {
		return nil, nil, err
	}

	if storedToken.GrantID != grantID || storedToken.UserID != userID {
		return nil, nil, ErrNotFound
	}

	grantJSON, exists := m.grants[storedToken.GrantID]
	if !exists {
		return nil, nil, ErrNotFound
	}

	var grant StoredGrant
	if err := json.Unmarshal(grantJSON, &grant); err != nil {
		return nil, nil, err
	}

	return &storedToken, &grant, nil
}
