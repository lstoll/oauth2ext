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
	AuthCode *string
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
	RefreshToken *string
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time

	// TODO -acr, AMR etc.
}

type Storage interface {
	CreateGrant(ctx context.Context, grant *StoredGrant) error
	UpdateGrant(ctx context.Context, grant *StoredGrant) error
	ExpireGrant(ctx context.Context, id uuid.UUID) error
	GetGrant(ctx context.Context, id uuid.UUID) (*StoredGrant, error)
	GetGrantByAuthCode(ctx context.Context, authCode string) (*StoredGrant, error)
	GetGrantByRefreshToken(ctx context.Context, refreshToken string) (*StoredGrant, error)
}
