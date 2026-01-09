package oauth2as

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	// MetadataDPoPThumbprint is the metadata key for storing the DPoP JWK thumbprint
	MetadataDPoPThumbprint = "dpop_thumbprint"
)

// TokenWithExpiry represents a token that is issued for a grant, that has an
// explicity expiration time.
type TokenWithExpiry struct {
	Token     []byte    `json:"token,omitzero"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
}

type StoredGrant struct {
	// ID is the unique identifier for this grant.
	ID uuid.UUID `json:"id,omitzero"`
	// AuthCode is the authorization code for the initial token exchange.
	AuthCode *TokenWithExpiry `json:"authCode,omitzero"`
	// UserID is the user ID that was granted access.
	UserID string `json:"userId,omitzero"`
	// ClientID is the client ID that was granted access.
	ClientID string `json:"clientId,omitzero"`
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string `json:"grantedScopes,omitzero"`
	// Request captures the request that was used to grant access. Used for
	// finalizing the code flow.
	Request *AuthRequest `json:"request,omitzero"`
	// RefreshToken is the refresh token for the grant.
	RefreshToken *TokenWithExpiry `json:"refreshToken,omitzero"`
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time `json:"grantedAt,omitzero"`
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time `json:"expiresAt,omitzero"`

	// AdditionalState contains additional internal state this library uses. It
	// should not be interacted with directly.
	AdditionalState json.RawMessage `json:"additionalState,omitzero"`

	// Metadata is arbitrary application-specific metadata that can be stored
	// with the grant. .
	Metadata []byte `json:"metadata,omitzero"`
	// EncryptedMetadata stores the application-specific encrypted metadata
	// associated with this grant.
	EncryptedMetadata []byte `json:"encryptedMetadata,omitzero"`

	// TODO -acr, AMR etc.
}

type storedAdditionalState struct {
	DPoPThumbprint *string `json:"dpopThumbprint,omitzero"`
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
