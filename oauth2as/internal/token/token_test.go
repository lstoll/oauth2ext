package token

import (
	"bytes"
	"testing"
)

// setupDEKForToken generates a DEK, encrypts it to the token, and returns both
// the DEKHandle and the encrypted DEK.
func setupDEKForToken(t *Token) (*DEKHandle, error) {
	dek, err := GenerateDEK()
	if err != nil {
		return nil, err
	}
	encryptedDEK, err := dek.EncryptDEKToToken(t)
	if err != nil {
		return nil, err
	}
	handle, err := t.DEKHandle(encryptedDEK)
	if err != nil {
		return nil, err
	}
	return handle, nil
}

func TestTokenWorkflows(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      []byte
		additionalData []byte
		usage          Usage
	}{
		{
			name:           "simple text",
			plaintext:      []byte("hello world"),
			additionalData: []byte("grant123"),
			usage:          Usage{Name: "access_token", Prefix: "at"},
		},
		{
			name:           "empty plaintext",
			plaintext:      []byte(""),
			additionalData: []byte("grant456"),
			usage:          Usage{Name: "refresh_token", Prefix: "rt"},
		},
		{
			name:      "empty additional data",
			plaintext: []byte("secret data"),
			usage:     Usage{Name: "authorization_code", Prefix: "ac"},
		},
		{
			name:           "unicode text",
			plaintext:      []byte("Hello, 世界! 🌍"),
			additionalData: []byte("grant789"),
			usage:          Usage{Name: "id_token", Prefix: "id"},
		},
		{
			name:           "long text",
			plaintext:      []byte("This is a very long piece of text that should be encrypted and decrypted properly. It contains multiple sentences and should test the encryption/decryption functionality thoroughly."),
			additionalData: []byte("grant-long"),
			usage:          Usage{Name: "device_code", Prefix: "dc"},
		},
		{
			name:           "empty usage",
			plaintext:      []byte("test data"),
			additionalData: []byte("grant-empty-usage"),
			usage:          Usage{Name: "", Prefix: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantID := "grant-id"
			userID := "user-id"
			tokenID := "test-id-123"

			t.Run("new_token_workflow", func(t *testing.T) {
				tok := New(tt.usage, grantID, userID)

				userToken := tok.ToUser(tokenID)
				if userToken == "" {
					t.Error("User token should not be empty")
				}
				if tok.Stored() == nil || len(tok.Stored()) == 0 {
					t.Error("Stored field should not be empty")
				}
				if len(tok.encryption) != keyLength {
					t.Errorf("Encryption key should be %d bytes, got %d", keyLength, len(tok.encryption))
				}

				dekHandle, err := setupDEKForToken(&tok)
				if err != nil {
					t.Fatalf("Failed to setup DEK: %v", err)
				}

				encrypted, err := dekHandle.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}

				if bytes.Equal(encrypted, tt.plaintext) {
					t.Error("Encrypted data should not match plaintext")
				}

				decrypted, err := dekHandle.Decrypt(encrypted, tt.additionalData)
				if err != nil {
					t.Fatalf("Decrypt failed: %v", err)
				}

				if !bytes.Equal(decrypted, tt.plaintext) {
					t.Errorf("Decrypted data doesn't match original. Got %q, want %q", string(decrypted), tt.plaintext)
				}
			})

			t.Run("derived_token_workflow", func(t *testing.T) {
				tokenID := "test-id-456"
				originalToken := New(tt.usage, grantID, userID)
				userTokenStr := originalToken.ToUser(tokenID)

				parsedToken, err := ParseUserToken(userTokenStr, tt.usage)
				if err != nil {
					t.Fatalf("ParseUserToken failed: %v", err)
				}

				if parsedToken.ID() != tokenID {
					t.Errorf("Parsed token ID mismatch. Got %s, want %s", parsedToken.ID(), tokenID)
				}
				if parsedToken.Payload().GetGrantId() != grantID {
					t.Errorf("Parsed token GrantID mismatch. Got %s, want %s", parsedToken.Payload().GetGrantId(), grantID)
				}

				derivedToken, err := parsedToken.Verify(tt.usage, originalToken.Stored(), grantID, userID)
				if err != nil {
					t.Fatalf("Verify failed: %v", err)
				}

				if derivedToken.ToUser(tokenID) != originalToken.ToUser(tokenID) {
					t.Error("Derived token User should match original")
				}
				if !bytes.Equal(derivedToken.Stored(), originalToken.Stored()) {
					t.Error("Derived token Stored should match original")
				}
				if !bytes.Equal(derivedToken.encryption, originalToken.encryption) {
					t.Error("Derived token Encryption key should match original")
				}

				// Generate a DEK and encrypt it to both tokens
				dek, err := GenerateDEK()
				if err != nil {
					t.Fatalf("Failed to generate DEK: %v", err)
				}
				encryptedDEKOriginal, err := dek.EncryptDEKToToken(&originalToken)
				if err != nil {
					t.Fatalf("Failed to encrypt DEK to original token: %v", err)
				}
				encryptedDEKDerived, err := dek.EncryptDEKToToken(derivedToken)
				if err != nil {
					t.Fatalf("Failed to encrypt DEK to derived token: %v", err)
				}

				originalHandle, err := originalToken.DEKHandle(encryptedDEKOriginal)
				if err != nil {
					t.Fatalf("Failed to get DEK handle from original token: %v", err)
				}
				derivedHandle, err := derivedToken.DEKHandle(encryptedDEKDerived)
				if err != nil {
					t.Fatalf("Failed to get DEK handle from derived token: %v", err)
				}

				encrypted, err := derivedHandle.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Fatalf("Encrypt with derived token failed: %v", err)
				}

				decrypted, err := originalHandle.Decrypt(encrypted, tt.additionalData)
				if err != nil {
					t.Fatalf("Decrypt with original token failed: %v", err)
				}

				if !bytes.Equal(decrypted, tt.plaintext) {
					t.Errorf("Decrypted data doesn't match original. Got %q, want %q", decrypted, tt.plaintext)
				}

				encrypted2, err := originalHandle.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Fatalf("Encrypt with original token failed: %v", err)
				}

				decrypted2, err := derivedHandle.Decrypt(encrypted2, tt.additionalData)
				if err != nil {
					t.Fatalf("Decrypt with derived token failed: %v", err)
				}

				if !bytes.Equal(decrypted2, tt.plaintext) {
					t.Errorf("Reverse decrypted data doesn't match original. Got %q, want %q", decrypted2, tt.plaintext)
				}
			})
		})
	}
}

func TestUsageDomainSeparation(t *testing.T) {
	plaintext := []byte("test data")
	additionalData := []byte("grant123")
	grantID := "grant-id"
	userID := "user-id"
	tokenID := "test-id-sep"

	usage1 := Usage{Name: "access_token", Prefix: "at"}
	usage2 := Usage{Name: "refresh_token", Prefix: "rt"}
	usage3 := Usage{Name: "authorization_code", Prefix: "ac"}

	token1 := New(usage1, grantID, userID)
	token2 := New(usage2, grantID, userID)
	token3 := New(usage3, grantID, userID)

	if token1.ToUser(tokenID) == token2.ToUser(tokenID) {
		t.Error("Tokens with different usage should have different user tokens")
	}
	if token1.ToUser(tokenID) == token3.ToUser(tokenID) {
		t.Error("Tokens with different usage should have different user tokens")
	}
	if token2.ToUser(tokenID) == token3.ToUser(tokenID) {
		t.Error("Tokens with different usage should have different user tokens")
	}

	// Generate a DEK and encrypt it to token1
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}
	encryptedDEK1, err := dek.EncryptDEKToToken(&token1)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK to token1: %v", err)
	}
	dekHandle1, err := token1.DEKHandle(encryptedDEK1)
	if err != nil {
		t.Fatalf("Failed to get DEK handle from token1: %v", err)
	}

	// Generate a separate DEK for token2
	dek2, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK for token2: %v", err)
	}
	encryptedDEK2, err := dek2.EncryptDEKToToken(&token2)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK to token2: %v", err)
	}
	dekHandle2, err := token2.DEKHandle(encryptedDEK2)
	if err != nil {
		t.Fatalf("Failed to get DEK handle from token2: %v", err)
	}

	encrypted1, err := dekHandle1.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with token1 failed: %v", err)
	}

	encrypted2, err := dekHandle2.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with token2 failed: %v", err)
	}

	if _, err := dekHandle2.Decrypt(encrypted1, additionalData); err == nil {
		t.Error("Token2 should not be able to decrypt token1's data")
	}

	if _, err := dekHandle1.Decrypt(encrypted2, additionalData); err == nil {
		t.Error("Token1 should not be able to decrypt token2's data")
	}

	userTokenStr1 := token1.ToUser(tokenID)
	parsedToken1, err := ParseUserToken(userTokenStr1, usage1)
	if err != nil {
		t.Fatalf("ParseUserToken failed: %v", err)
	}

	derivedToken1, err := parsedToken1.Verify(usage1, token1.Stored(), grantID, userID)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Encrypt the same DEK to the derived token (which has the same encryption key as token1)
	encryptedDEKDerived, err := dek.EncryptDEKToToken(derivedToken1)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK to derived token: %v", err)
	}

	derivedHandle, err := derivedToken1.DEKHandle(encryptedDEKDerived)
	if err != nil {
		t.Fatalf("Failed to get DEK handle from derived token: %v", err)
	}

	// The derived token should be able to decrypt data encrypted with the original token's DEK
	decrypted, err := derivedHandle.Decrypt(encrypted1, additionalData)
	if err != nil {
		t.Errorf("Derived token should be able to decrypt original data: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match original. Got %q, want %q", decrypted, plaintext)
	}
}

func TestUsageMismatch(t *testing.T) {
	grantID := "grant-id"
	userID := "user-id"
	tokenID := "test-id-mismatch"
	usage1 := Usage{Name: "access_token", Prefix: "at"}
	usage2 := Usage{Name: "refresh_token", Prefix: "rt"}
	usageEmpty := Usage{Name: "", Prefix: ""}

	originalToken := New(usage1, grantID, userID)
	userTokenStr := originalToken.ToUser(tokenID)

	if _, err := ParseUserToken(userTokenStr, usage2); err == nil {
		t.Error("ParseUserToken with wrong usage should fail due to prefix mismatch")
	}

	if _, err := ParseUserToken(userTokenStr, usageEmpty); err == nil {
		t.Error("ParseUserToken with empty usage should fail due to prefix mismatch")
	}

	parsedTokenCorrect, err := ParseUserToken(userTokenStr, usage1)
	if err != nil {
		t.Fatalf("ParseUserToken with correct usage should work: %v", err)
	}

	derivedTokenCorrect, err := parsedTokenCorrect.Verify(usage1, originalToken.Stored(), grantID, userID)
	if err != nil {
		t.Fatalf("Verify with correct usage should work: %v", err)
	}

	if derivedTokenCorrect.ToUser(tokenID) != originalToken.ToUser(tokenID) {
		t.Error("Derived token User should match original")
	}

	plaintext := []byte("test data")
	additionalData := []byte("grant123")

	// Generate a DEK and encrypt it to both tokens
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}
	encryptedDEKOriginal, err := dek.EncryptDEKToToken(&originalToken)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK to original token: %v", err)
	}
	encryptedDEKDerived, err := dek.EncryptDEKToToken(derivedTokenCorrect)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK to derived token: %v", err)
	}

	originalHandle, err := originalToken.DEKHandle(encryptedDEKOriginal)
	if err != nil {
		t.Fatalf("Failed to get DEK handle from original token: %v", err)
	}
	derivedHandle, err := derivedTokenCorrect.DEKHandle(encryptedDEKDerived)
	if err != nil {
		t.Fatalf("Failed to get DEK handle from derived token: %v", err)
	}

	encryptedOriginal, err := originalHandle.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with original token failed: %v", err)
	}

	decrypted, err := derivedHandle.Decrypt(encryptedOriginal, additionalData)
	if err != nil {
		t.Errorf("Token with correct usage should be able to decrypt original's data: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted data doesn't match original. Got %q, want %q", decrypted, plaintext)
	}
}

func TestTokenErrorCases(t *testing.T) {
	grantID := "grant-id"
	userID := "user-id"
	tokenID := "test-id-errors"
	usage := Usage{Name: "access_token", Prefix: "at"}

	tests := []struct {
		name      string
		userToken string
		usage     Usage
		wantErr   bool
	}{
		{
			name:      "invalid base64 user token",
			userToken: "invalid-base64!",
			usage:     usage,
			wantErr:   true,
		},
		{
			name:      "malformed user token - missing parts",
			userToken: "o2asat_invalid",
			usage:     usage,
			wantErr:   true,
		},
		{
			name:      "valid user token",
			userToken: New(usage, grantID, userID).ToUser(tokenID),
			usage:     usage,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseUserToken(tt.userToken, tt.usage)
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEncryptionErrorCases(t *testing.T) {
	usage := Usage{Name: "access_token", Prefix: "at"}
	grantID := "grant-id"
	userID := "user-id"
	tok := New(usage, grantID, userID)
	plaintext := []byte("test data")
	additionalData := []byte("grant123")

	dekHandle, err := setupDEKForToken(&tok)
	if err != nil {
		t.Fatalf("Failed to setup DEK: %v", err)
	}

	encrypted, err := dekHandle.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Setup encryption failed: %v", err)
	}

	tests := []struct {
		name           string
		ciphertext     []byte
		additionalData []byte
		wantErr        bool
	}{
		{
			name:           "wrong additional data",
			ciphertext:     encrypted,
			additionalData: []byte("wrong-grant"),
			wantErr:        true,
		},
		{
			name:           "corrupted ciphertext",
			ciphertext:     append(encrypted[:len(encrypted)-1], 0xFF),
			additionalData: additionalData,
			wantErr:        true,
		},
		{
			name:           "too short ciphertext",
			ciphertext:     []byte{1, 2, 3, 4, 5},
			additionalData: additionalData,
			wantErr:        true,
		},
		{
			name:           "empty ciphertext",
			ciphertext:     []byte{},
			additionalData: additionalData,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dekHandle.Decrypt(tt.ciphertext, tt.additionalData)
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTokenConsistency(t *testing.T) {
	grantID := "grant-id"
	userID := "user-id"
	tokenID := "test-id-consistency"
	usage := Usage{Name: "access_token", Prefix: "at"}

	originalToken := New(usage, grantID, userID)
	userTokenStr := originalToken.ToUser(tokenID)

	parsedToken1, err := ParseUserToken(userTokenStr, usage)
	if err != nil {
		t.Fatalf("ParseUserToken failed: %v", err)
	}
	token1, err := parsedToken1.Verify(usage, originalToken.Stored(), grantID, userID)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	parsedToken2, err := ParseUserToken(userTokenStr, usage)
	if err != nil {
		t.Fatalf("ParseUserToken failed: %v", err)
	}
	token2, err := parsedToken2.Verify(usage, originalToken.Stored(), grantID, userID)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if token1.ToUser(tokenID) != token2.ToUser(tokenID) {
		t.Error("User field should be identical")
	}
	if !bytes.Equal(token1.Stored(), token2.Stored()) {
		t.Error("Stored fields should be identical")
	}
	if !bytes.Equal(token1.encryption, token2.encryption) {
		t.Error("Encryption keys should be identical")
	}

	token3 := New(usage, grantID, userID)
	if token1.ToUser(tokenID) == token3.ToUser(tokenID) {
		t.Error("Different tokens should have different user tokens")
	}
	if bytes.Equal(token1.Stored(), token3.Stored()) {
		t.Error("Different tokens should have different stored tokens")
	}
}

func TestVerifyMismatches(t *testing.T) {
	grantID := "grant-id"
	userID := "user-id"
	tokenID := "test-id-mismatch"
	usage := Usage{Name: "access_token", Prefix: "at"}

	originalToken := New(usage, grantID, userID)
	userTokenStr := originalToken.ToUser(tokenID)

	parsedToken, err := ParseUserToken(userTokenStr, usage)
	if err != nil {
		t.Fatalf("ParseUserToken failed: %v", err)
	}

	// Mismatch Grant ID
	if _, err := parsedToken.Verify(usage, originalToken.Stored(), "wrong-grant", userID); err == nil {
		t.Error("Verify should fail with wrong grant ID")
	}

	// Mismatch User ID
	if _, err := parsedToken.Verify(usage, originalToken.Stored(), grantID, "wrong-user"); err == nil {
		t.Error("Verify should fail with wrong user ID")
	}

	// Success
	if _, err := parsedToken.Verify(usage, originalToken.Stored(), grantID, userID); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
}
