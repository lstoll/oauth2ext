package oauth2as

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type StoredGrant struct {
	// ID is the unique identifier for this grant.
	ID uuid.UUID
	// AuthCode is the authorization code for the initial token exchange.
	AuthCode []byte
	// UserID is the user ID that was granted access.
	UserID string
	// ClientID is the client ID that was granted access.
	ClientID string
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string
	// Request captures the request that was used to grant access. Used for
	// finalizing the code flow.
	Request *AuthRequest
	// RefreshToken is the refresh token for the grant.
	RefreshToken []byte
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time

	// Metadata is arbitrary metadata that can be stored with the grant.
	Metadata map[string]string
	// EncryptedMetadata stores the encrypted metadata associated with this
	// grant.
	EncryptedMetadata []byte

	// TODO -acr, AMR etc.
}

// Storage is the interface for storing and retrieving grants.
type Storage interface {
	// CreateGrant creates a new grant.
	CreateGrant(ctx context.Context, grant *StoredGrant) error
	// UpdateGrant updates an existing grant.
	UpdateGrant(ctx context.Context, grant *StoredGrant) error
	// ExpireGrant expires a grant.
	ExpireGrant(ctx context.Context, id uuid.UUID) error
	// GetGrant retrieves a grant by ID. If no grant is found, it should return
	// a nil grant.
	GetGrant(ctx context.Context, id uuid.UUID) (*StoredGrant, error)
	// GetGrantByAuthCode retrieves a grant by authorization code. If no grant
	// is found, it should return a nil grant. The code is a raw byte slice.
	GetGrantByAuthCode(ctx context.Context, authCode []byte) (*StoredGrant, error)
	// GetGrantByRefreshToken retrieves a grant by refresh token. If no grant
	// is found, it should return a nil grant. The token is a raw byte slice.
	GetGrantByRefreshToken(ctx context.Context, refreshToken []byte) (*StoredGrant, error)
}
