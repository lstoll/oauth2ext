package oauth2as

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a grant cannot be found in storage.
	ErrNotFound = errors.New("not found")
	// ErrConcurrentUpdate is returned when an update fails due to a version mismatch.
	ErrConcurrentUpdate = errors.New("concurrent update detected")
)

const (
	// MetadataDPoPThumbprint is the metadata key for storing the DPoP JWK thumbprint
	MetadataDPoPThumbprint = "dpop_thumbprint"
)

// StoredAuthCode represents an authorization code that is issued during the
// authorization flow. Auth codes are short-lived and single-use.
type StoredAuthCode struct {
	Code    []byte `json:"code,omitzero"`
	GrantID string `json:"grantId,omitzero"`
	UserID  string `json:"userId,omitzero"`
	// ValidUntil is the time at which the code is no longer valid for use.
	ValidUntil time.Time `json:"validUntil,omitzero"`
	// StorageExpiresAt is the time at which the code can be deleted from storage.
	// This is typically after ValidUntil to allow for cleanup.
	StorageExpiresAt time.Time `json:"storageExpiresAt,omitzero"`
	// EncryptedGrantKey is the key used to encrypt the grant metadata, encrypted
	// with this auth code.
	EncryptedGrantKey []byte `json:"encryptedGrantKey,omitzero"`
	// Version is the version of the stored code, used for optimistic locking.
	Version int64 `json:"version,omitzero"`
}

// StoredRefreshToken represents a refresh token that can be used to obtain new
// access tokens. Refresh tokens are long-lived and support rotation with grace periods.
type StoredRefreshToken struct {
	Token   []byte `json:"token,omitzero"`
	GrantID string `json:"grantId,omitzero"`
	UserID  string `json:"userId,omitzero"`
	// ValidUntil is the time at which the token is no longer valid for use.
	ValidUntil time.Time `json:"validUntil,omitzero"`
	// StorageExpiresAt is the time at which the token can be deleted from storage.
	// This is typically after ValidUntil plus any grace period.
	StorageExpiresAt time.Time `json:"storageExpiresAt,omitzero"`
	// ReplacedByTokenID is the ID of the token that replaced this one during rotation.
	// Used for tracking rotation chains and enforcing grace period policies.
	ReplacedByTokenID string `json:"replacedByTokenID,omitzero"`
	// EncryptedGrantKey is the key used to encrypt the grant metadata, encrypted
	// with this refresh token.
	EncryptedGrantKey []byte `json:"encryptedGrantKey,omitzero"`
	// Version is the version of the stored token, used for optimistic locking.
	Version int64 `json:"version,omitzero"`
}

type StoredGrant struct {
	// UserID is the user ID that was granted access.
	UserID string `json:"userId,omitzero"`
	// ClientID is the client ID that was granted access.
	ClientID string `json:"clientId,omitzero"`
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string `json:"grantedScopes,omitzero"`
	// Request captures the request that was used to grant access. Used for
	// finalizing the code flow.
	Request *AuthRequest `json:"request,omitzero"`
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time `json:"grantedAt,omitzero"`
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time `json:"expiresAt,omitzero"`

	// AdditionalState contains internal protocol state managed by this library
	// (e.g., DPoP thumbprints, certificate bindings). This field allows the
	// library to evolve its internal state schema without breaking the Storage
	// interface contract. Storage implementations MUST preserve this field but
	// SHOULD NOT inspect or modify its contents.
	//
	// Applications should use the Metadata/EncryptedMetadata fields for their
	// own data.
	AdditionalState json.RawMessage `json:"additionalState,omitzero"`

	// Metadata stores unencrypted application-specific data that can be accessed
	// without a valid token (e.g., grant creation timestamp, grant type).
	Metadata []byte `json:"metadata,omitzero"`
	// EncryptedMetadata stores sensitive application data encrypted with the
	// Grant Key. Only accessible with a valid token from this grant.
	//
	// Common use case: storing upstream IDP refresh tokens when this AS acts
	// as an OAuth2 client to another provider. The upstream refresh token is
	// encrypted here and can only be decrypted by presenting a valid token.
	EncryptedMetadata []byte `json:"encryptedMetadata,omitzero"`
	// Version is the version of the stored grant, used for optimistic locking.
	Version int64 `json:"version,omitzero"`

	// TODO: Add ACR (Authentication Context Class Reference) and AMR (Authentication Methods References) fields
}

type storedAdditionalState struct {
	DPoPThumbprint *string `json:"dpopThumbprint,omitzero"`
}

// Storage is the interface for storing and retrieving grants, authorization codes, and refresh tokens.
type Storage interface {
	// CreateGrant creates a new grant and returns a unique opaque identifier.
	// The ID format is implementation-defined and should be treated as an
	// opaque string.
	CreateGrant(ctx context.Context, grant *StoredGrant) (id string, err error)
	// UpdateGrant updates an existing grant. Returns ErrNotFound if the
	// grant does not exist. Implementations MUST perform an optimistic locking
	// check using the Version field. If the stored version does not match the
	// version in the provided grant, it MUST return ErrConcurrentUpdate. On
	// success, the stored version MUST be incremented.
	UpdateGrant(ctx context.Context, id string, grant *StoredGrant) error
	// ExpireGrant expires a grant and optionally deletes associated
	// tokens/codes. Implementations MAY choose to delete associated tokens or
	// leave them for garbage collection. Returns nil if the grant does not
	// exist.
	ExpireGrant(ctx context.Context, id string) error
	// GetGrant retrieves a grant by ID. Returns ErrNotFound if the grant
	// does not exist.
	GetGrant(ctx context.Context, id string) (*StoredGrant, error)

	// CreateAuthCode creates a new authorization code associated with a grant and
	// returns a unique opaque identifier. Auth codes are short-lived and single-use.
	CreateAuthCode(ctx context.Context, userID, grantID, codeID string, code *StoredAuthCode) error
	// ExpireAuthCode expires an authorization code. Returns ErrNotFound if the
	// code was not found.
	ExpireAuthCode(ctx context.Context, userID, grantID, codeID string) error
	// GetAuthCodeAndGrant retrieves an auth code and its associated grant by
	// code ID. Returns ErrNotFound if the code does not exist.
	GetAuthCodeAndGrant(ctx context.Context, userID, grantID, codeID string) (*StoredAuthCode, *StoredGrant, error)

	// CreateRefreshToken creates a new refresh token associated with a grant
	// and returns a unique opaque identifier. Refresh tokens are long-lived and
	// support rotation.
	CreateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *StoredRefreshToken) error
	// UpdateRefreshToken updates an existing refresh token. Returns
	// ErrNotFound if the token does not exist. Used for updating rotation
	// tracking fields. Implementations MUST perform an optimistic locking check
	// using the Version field. If the stored version does not match the version
	// in the provided token, it MUST return ErrConcurrentUpdate. On success,
	// the stored version MUST be incremented.
	UpdateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *StoredRefreshToken) error
	// ExpireRefreshToken expires a refresh token. Returns ErrNotFound if the token was not found.
	ExpireRefreshToken(ctx context.Context, userID, grantID, tokenID string) error
	// GetRefreshTokenAndGrant retrieves a refresh token and its associated grant by token ID.
	// Returns ErrNotFound if the token does not exist.
	GetRefreshTokenAndGrant(ctx context.Context, userID, grantID, tokenID string) (*StoredRefreshToken, *StoredGrant, error)
}
