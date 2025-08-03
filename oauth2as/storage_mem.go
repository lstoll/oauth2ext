package oauth2as

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"sync"

	"github.com/google/uuid"
)

// MemStorage implements the Storage interface with an in-memory dataset.
// All items return nil when not found.
type MemStorage struct {
	mu sync.RWMutex
	// grants stores grants by their ID
	grants map[uuid.UUID]*StoredGrant
	// authCodes maps authorization codes to grant IDs
	authCodes map[string]uuid.UUID
	// refreshTokens maps refresh tokens to grant IDs
	refreshTokens map[string]uuid.UUID
}

// NewMemStorage creates a new in-memory storage instance.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		grants:        make(map[uuid.UUID]*StoredGrant),
		authCodes:     make(map[string]uuid.UUID),
		refreshTokens: make(map[string]uuid.UUID),
	}
}

// CreateGrant stores a new grant in memory.
func (m *MemStorage) CreateGrant(ctx context.Context, grant *StoredGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store the grant by ID
	m.grants[grant.ID] = grant

	// Store auth code mapping if present
	if len(grant.AuthCode) > 0 {
		m.authCodes[hex.EncodeToString(grant.AuthCode)] = grant.ID
	}

	// Store refresh token mapping if present
	if len(grant.RefreshToken) > 0 {
		m.refreshTokens[hex.EncodeToString(grant.RefreshToken)] = grant.ID
	}

	return nil
}

// UpdateGrant updates an existing grant in memory.
func (m *MemStorage) UpdateGrant(ctx context.Context, grant *StoredGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the existing grant to update mappings
	existing, exists := m.grants[grant.ID]
	if !exists {
		return nil // Grant doesn't exist, nothing to update
	}

	// Remove old auth code mapping if it changed
	if len(existing.AuthCode) > 0 && (len(grant.AuthCode) == 0 || subtle.ConstantTimeCompare(existing.AuthCode, grant.AuthCode) == 0) {
		delete(m.authCodes, hex.EncodeToString(existing.AuthCode))
	}

	// Remove old refresh token mapping if it changed
	if len(existing.RefreshToken) > 0 && (len(grant.RefreshToken) == 0 || subtle.ConstantTimeCompare(existing.RefreshToken, grant.RefreshToken) == 0) {
		delete(m.refreshTokens, hex.EncodeToString(existing.RefreshToken))
	}

	// Update the grant
	m.grants[grant.ID] = grant

	// Add new auth code mapping if present
	if len(grant.AuthCode) > 0 {
		m.authCodes[hex.EncodeToString(grant.AuthCode)] = grant.ID
	}

	// Add new refresh token mapping if present
	if len(grant.RefreshToken) > 0 {
		m.refreshTokens[hex.EncodeToString(grant.RefreshToken)] = grant.ID
	}

	return nil
}

// ExpireGrant removes a grant from memory.
func (m *MemStorage) ExpireGrant(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	grant, exists := m.grants[id]
	if !exists {
		return nil // Grant doesn't exist, nothing to expire
	}

	// Remove auth code mapping if present
	if len(grant.AuthCode) > 0 {
		delete(m.authCodes, hex.EncodeToString(grant.AuthCode))
	}

	// Remove refresh token mapping if present
	if len(grant.RefreshToken) > 0 {
		delete(m.refreshTokens, hex.EncodeToString(grant.RefreshToken))
	}

	// Remove the grant
	delete(m.grants, id)

	return nil
}

// GetGrant retrieves a grant by its ID. Returns nil if not found.
func (m *MemStorage) GetGrant(ctx context.Context, id uuid.UUID) (*StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grant, exists := m.grants[id]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modifications
	return copyStoredGrant(grant), nil
}

// GetGrantByAuthCode retrieves a grant by its authorization code. Returns nil if not found.
func (m *MemStorage) GetGrantByAuthCode(ctx context.Context, authCode []byte) (*StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grantID, exists := m.authCodes[hex.EncodeToString(authCode)]
	if !exists {
		return nil, nil
	}

	grant, exists := m.grants[grantID]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modifications
	return copyStoredGrant(grant), nil
}

// GetGrantByRefreshToken retrieves a grant by its refresh token. Returns nil if not found.
func (m *MemStorage) GetGrantByRefreshToken(ctx context.Context, refreshToken []byte) (*StoredGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grantID, exists := m.refreshTokens[hex.EncodeToString(refreshToken)]
	if !exists {
		return nil, nil
	}

	grant, exists := m.grants[grantID]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent external modifications
	return copyStoredGrant(grant), nil
}

// copyStoredGrant creates a deep copy of a StoredGrant to prevent external modifications.
func copyStoredGrant(grant *StoredGrant) *StoredGrant {
	if grant == nil {
		return nil
	}

	copied := &StoredGrant{
		ID:            grant.ID,
		UserID:        grant.UserID,
		ClientID:      grant.ClientID,
		GrantedScopes: make([]string, len(grant.GrantedScopes)),
		GrantedAt:     grant.GrantedAt,
		ExpiresAt:     grant.ExpiresAt,
	}

	// Copy slices
	copy(copied.GrantedScopes, grant.GrantedScopes)

	// Copy pointers
	if len(grant.AuthCode) > 0 {
		copied.AuthCode = make([]byte, len(grant.AuthCode))
		copy(copied.AuthCode, grant.AuthCode)
	}

	if len(grant.RefreshToken) > 0 {
		copied.RefreshToken = make([]byte, len(grant.RefreshToken))
		copy(copied.RefreshToken, grant.RefreshToken)
	}

	// Copy AuthRequest if present
	if grant.Request != nil {
		copied.Request = &AuthRequest{
			ClientID:      grant.Request.ClientID,
			RedirectURI:   grant.Request.RedirectURI,
			State:         grant.Request.State,
			Scopes:        make([]string, len(grant.Request.Scopes)),
			CodeChallenge: grant.Request.CodeChallenge,
			ACRValues:     make([]string, len(grant.Request.ACRValues)),
			Raw:           grant.Request.Raw, // This is a reference, but we'll keep it as is
		}
		copy(copied.Request.Scopes, grant.Request.Scopes)
		copy(copied.Request.ACRValues, grant.Request.ACRValues)
	}

	return copied
}
