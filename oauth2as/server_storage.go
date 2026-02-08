package oauth2as

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"lds.li/oauth2ext/oauth2as/internal/token"
)

var (
	errGrantNotFound     = errors.New("grant not found")
	errGrantTokenInvalid = errors.New("grant token invalid")
	errGrantExpired      = errors.New("grant expired")
)

// grantLoader is an interface that represents a loaded grant, regardless of
// how it was loaded (auth code or refresh token).
type grantLoader interface {
	Grant() *StoredGrant
	GrantID() string
	DecryptedMetadata() []byte
	SetDecryptedMetadata([]byte)
	AdditionalState() *storedAdditionalState
	SetAdditionalState(storedAdditionalState)
}

// loadedAuthCodeGrant represents a grant loaded via an authorization code.
// Auth codes are simpler - they don't support rotation or encrypted grant keys.
type loadedAuthCodeGrant struct {
	grant             *StoredGrant
	grantID           string
	authCode          *StoredAuthCode
	decryptedMetadata []byte
	additionalState   storedAdditionalState
	grantKey          *token.DEKHandle
}

func (l *loadedAuthCodeGrant) Grant() *StoredGrant              { return l.grant }
func (l *loadedAuthCodeGrant) GrantID() string                  { return l.grantID }
func (l *loadedAuthCodeGrant) DecryptedMetadata() []byte        { return l.decryptedMetadata }
func (l *loadedAuthCodeGrant) SetDecryptedMetadata(data []byte) { l.decryptedMetadata = data }
func (l *loadedAuthCodeGrant) AdditionalState() *storedAdditionalState {
	return &l.additionalState
}
func (l *loadedAuthCodeGrant) SetAdditionalState(state storedAdditionalState) {
	l.additionalState = state
}

// loadedRefreshTokenGrant represents a grant loaded via a refresh token.
// Refresh tokens support rotation, grace periods, and encrypted grant keys.
type loadedRefreshTokenGrant struct {
	grant             *StoredGrant
	grantID           string
	refreshToken      *StoredRefreshToken
	decryptedMetadata []byte
	additionalState   storedAdditionalState
	grantKey          *token.DEKHandle
}

func (l *loadedRefreshTokenGrant) Grant() *StoredGrant              { return l.grant }
func (l *loadedRefreshTokenGrant) GrantID() string                  { return l.grantID }
func (l *loadedRefreshTokenGrant) DecryptedMetadata() []byte        { return l.decryptedMetadata }
func (l *loadedRefreshTokenGrant) SetDecryptedMetadata(data []byte) { l.decryptedMetadata = data }
func (l *loadedRefreshTokenGrant) AdditionalState() *storedAdditionalState {
	return &l.additionalState
}
func (l *loadedRefreshTokenGrant) SetAdditionalState(state storedAdditionalState) {
	l.additionalState = state
}

func (s *Server) getGrantFromAuthCode(ctx context.Context, presentedCode string) (*loadedAuthCodeGrant, error) {
	parsedCode, err := token.ParseUserToken(presentedCode, tokenUsageAuthCode)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedCode, grant, err := s.config.Storage.GetAuthCodeAndGrant(ctx, parsedCode.ID())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, errGrantNotFound
		}
		return nil, fmt.Errorf("failed to get grant from auth code: %w", err)
	}

	// Check if the code has been garbage collected or is absolutely expired
	if s.now().After(storedCode.StorageExpiresAt) {
		return nil, errGrantExpired
	}

	if s.now().After(grant.ExpiresAt) {
		return nil, errGrantExpired
	}

	verifiedToken, err := parsedCode.Verify(tokenUsageAuthCode, storedCode.Code, storedCode.GrantID, grant.UserID)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	loadedGrant := &loadedAuthCodeGrant{
		grant:    grant,
		grantID:  storedCode.GrantID,
		authCode: storedCode,
	}

	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &loadedGrant.additionalState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}

	if len(storedCode.EncryptedGrantKey) > 0 {
		loadedGrant.grantKey, err = verifiedToken.DEKHandle(storedCode.EncryptedGrantKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt grant key: %w", err)
		}
	}

	if len(grant.EncryptedMetadata) > 0 {
		if loadedGrant.grantKey == nil {
			return nil, fmt.Errorf("grant missing encryption key")
		}
		loadedGrant.decryptedMetadata, err = loadedGrant.grantKey.Decrypt(grant.EncryptedMetadata, []byte(storedCode.GrantID))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata with grant key: %w", err)
		}
	}

	return loadedGrant, nil
}

func (s *Server) getGrantFromRefreshToken(ctx context.Context, presentedToken string) (*loadedRefreshTokenGrant, error) {
	parsedToken, err := token.ParseUserToken(presentedToken, tokenUsageRefresh)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedToken, grant, err := s.config.Storage.GetRefreshTokenAndGrant(ctx, parsedToken.ID())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, errGrantNotFound
		}
		return nil, fmt.Errorf("failed to get grant from refresh token: %w", err)
	}

	// Check if the token has been garbage collected or is absolutely expired
	if s.now().After(storedToken.StorageExpiresAt) {
		return nil, errGrantExpired
	}

	if s.now().After(grant.ExpiresAt) {
		return nil, errGrantExpired
	}

	verifiedToken, err := parsedToken.Verify(tokenUsageRefresh, storedToken.Token, storedToken.GrantID, grant.UserID)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	loadedGrant := &loadedRefreshTokenGrant{
		grant:        grant,
		grantID:      storedToken.GrantID,
		refreshToken: storedToken,
	}

	if len(storedToken.EncryptedGrantKey) > 0 {
		loadedGrant.grantKey, err = verifiedToken.DEKHandle(storedToken.EncryptedGrantKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt grant key: %w", err)
		}
	}

	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &loadedGrant.additionalState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}

	if len(grant.EncryptedMetadata) > 0 {
		if loadedGrant.grantKey == nil {
			return nil, fmt.Errorf("grant missing encryption key")
		}
		loadedGrant.decryptedMetadata, err = loadedGrant.grantKey.Decrypt(grant.EncryptedMetadata, []byte(storedToken.GrantID))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata with grant key: %w", err)
		}
	}

	return loadedGrant, nil
}

// putGrantWithAuthCode creates the grant and auth code, returning grant ID and token string.
func (s *Server) putGrantWithAuthCode(ctx context.Context, loadedGrant *loadedAuthCodeGrant, codeExpiresAt time.Time) (grantID string, tokenString string, err error) {
	addlb, err := json.Marshal(loadedGrant.additionalState)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal additional state: %w", err)
	}
	loadedGrant.grant.AdditionalState = addlb

	// Create the grant
	grid, err := s.config.Storage.CreateGrant(ctx, loadedGrant.grant)
	if err != nil {
		return "", "", fmt.Errorf("failed to create grant: %w", err)
	}

	// Create token
	tok := token.New(tokenUsageAuthCode, grid, loadedGrant.grant.UserID)

	var encryptedGrantKey []byte
	if len(loadedGrant.decryptedMetadata) > 0 {
		if loadedGrant.grantKey == nil {
			loadedGrant.grantKey, err = token.GenerateDEK()
			if err != nil {
				return "", "", fmt.Errorf("failed to generate grant key: %w", err)
			}
		}

		// Encrypt metadata with the Grant Key
		encryptedMetadata, err := loadedGrant.grantKey.Encrypt(loadedGrant.decryptedMetadata, []byte(grid))
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt metadata: %w", err)
		}
		loadedGrant.grant.EncryptedMetadata = encryptedMetadata

		// Update the grant with the encrypted metadata
		if err := s.config.Storage.UpdateGrant(ctx, grid, loadedGrant.grant); err != nil {
			return "", "", fmt.Errorf("failed to update grant with encrypted metadata: %w", err)
		}

		// Encrypt the Grant Key with the new Token
		encryptedGrantKey, err = loadedGrant.grantKey.EncryptDEKToToken(&tok)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt grant key: %w", err)
		}
	}

	cid := newUUIDv4()

	// Create the auth code
	err = s.config.Storage.CreateAuthCode(ctx, cid, &StoredAuthCode{
		GrantID:           grid,
		Code:              tok.Stored(),
		ValidUntil:        codeExpiresAt,
		StorageExpiresAt:  loadedGrant.grant.ExpiresAt, // Keep code around as long as the grant
		EncryptedGrantKey: encryptedGrantKey,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to create auth code: %w", err)
	}

	return grid, tok.ToUser(cid), nil
}

// putGrantWithRefreshToken creates or updates the grant including encrypted data
// and creates a new refresh token, returning grant ID, token string, and token ID.
func (s *Server) putGrantWithRefreshToken(ctx context.Context, loadedGrant *loadedRefreshTokenGrant, tokenExpiresAt time.Time) (grantID string, tokenString string, tokenID string, err error) {
	addlb, err := json.Marshal(loadedGrant.additionalState)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to marshal additional state: %w", err)
	}
	loadedGrant.grant.AdditionalState = addlb

	if len(loadedGrant.decryptedMetadata) > 0 {
		if loadedGrant.grantKey == nil {
			loadedGrant.grantKey, err = token.GenerateDEK()
			if err != nil {
				return "", "", "", fmt.Errorf("failed to generate grant key: %w", err)
			}
		}
	}

	var grid string

	if loadedGrant.grantID == "" {
		grid, err = s.config.Storage.CreateGrant(ctx, loadedGrant.grant)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to create grant: %w", err)
		}

		if len(loadedGrant.decryptedMetadata) > 0 {
			// Encrypt metadata with the Grant Key
			encryptedMetadata, err := loadedGrant.grantKey.Encrypt(loadedGrant.decryptedMetadata, []byte(grid))
			if err != nil {
				return "", "", "", fmt.Errorf("failed to encrypt metadata: %w", err)
			}
			loadedGrant.grant.EncryptedMetadata = encryptedMetadata

			if err := s.config.Storage.UpdateGrant(ctx, grid, loadedGrant.grant); err != nil {
				return "", "", "", fmt.Errorf("failed to update grant: %w", err)
			}
		}
	} else {
		grid = loadedGrant.grantID
		if len(loadedGrant.decryptedMetadata) > 0 {
			// Encrypt metadata with the Grant Key
			encryptedMetadata, err := loadedGrant.grantKey.Encrypt(loadedGrant.decryptedMetadata, []byte(grid))
			if err != nil {
				return "", "", "", fmt.Errorf("failed to encrypt metadata: %w", err)
			}
			loadedGrant.grant.EncryptedMetadata = encryptedMetadata
		}

		if err := s.config.Storage.UpdateGrant(ctx, loadedGrant.grantID, loadedGrant.grant); err != nil {
			return "", "", "", fmt.Errorf("failed to update grant: %w", err)
		}
	}

	tok := token.New(tokenUsageRefresh, grid, loadedGrant.grant.UserID)

	var encryptedGrantKey []byte
	if loadedGrant.grantKey != nil {
		encryptedGrantKey, err = loadedGrant.grantKey.EncryptDEKToToken(&tok)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to encrypt grant key: %w", err)
		}
	}

	tid := newUUIDv4()

	err = s.config.Storage.CreateRefreshToken(ctx, tid, &StoredRefreshToken{
		GrantID:           grid,
		Token:             tok.Stored(),
		ValidUntil:        tokenExpiresAt,
		StorageExpiresAt:  loadedGrant.grant.ExpiresAt, // Keep token around as long as the grant
		EncryptedGrantKey: encryptedGrantKey,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	return grid, tok.ToUser(tid), tid, nil
}
