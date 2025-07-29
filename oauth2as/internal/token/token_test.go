package token

import (
	"encoding/base64"
	"testing"
)

func TestTokenWorkflows(t *testing.T) {
	tests := []struct {
		name           string
		plaintext      string
		additionalData string
		usage          string
	}{
		{
			name:           "simple text",
			plaintext:      "hello world",
			additionalData: "grant123",
			usage:          "access_token",
		},
		{
			name:           "empty plaintext",
			plaintext:      "",
			additionalData: "grant456",
			usage:          "refresh_token",
		},
		{
			name:           "empty additional data",
			plaintext:      "secret data",
			additionalData: "",
			usage:          "authorization_code",
		},
		{
			name:           "unicode text",
			plaintext:      "Hello, 世界! 🌍",
			additionalData: "grant789",
			usage:          "id_token",
		},
		{
			name:           "long text",
			plaintext:      "This is a very long piece of text that should be encrypted and decrypted properly. It contains multiple sentences and should test the encryption/decryption functionality thoroughly.",
			additionalData: "grant-long",
			usage:          "device_code",
		},
		{
			name:           "empty usage",
			plaintext:      "test data",
			additionalData: "grant-empty-usage",
			usage:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test workflow 1: NewToken -> Encrypt -> Decrypt
			t.Run("new_token_workflow", func(t *testing.T) {
				// Create a new token
				token := New(tt.usage)

				// Verify token structure
				if token.User() == "" {
					t.Error("User field should not be empty")
				}
				if token.Stored() == nil || len(token.Stored()) == 0 {
					t.Error("Stored field should not be empty")
				}
				if len(token.encryption) != keyLength {
					t.Errorf("Encryption key should be %d bytes, got %d", keyLength, len(token.encryption))
				}

				// Verify tokens are valid base64
				_, err := base64.URLEncoding.DecodeString(token.User())
				if err != nil {
					t.Errorf("User token should be valid base64: %v", err)
				}

				// Encrypt data
				encrypted, err := token.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Errorf("Encrypt failed: %v", err)
					return
				}

				// Verify encrypted data is different from plaintext
				if string(encrypted) == tt.plaintext {
					t.Error("Encrypted data should not match plaintext")
				}

				// Decrypt data
				decrypted, err := token.Decrypt(encrypted, tt.additionalData)
				if err != nil {
					t.Errorf("Decrypt failed: %v", err)
					return
				}

				// Verify decrypted data matches original
				if string(decrypted) != tt.plaintext {
					t.Errorf("Decrypted data doesn't match original. Got %q, want %q", string(decrypted), tt.plaintext)
				}
			})

			// Test workflow 2: NewToken -> TokenFromUserToken -> Cross-encrypt/decrypt
			t.Run("derived_token_workflow", func(t *testing.T) {
				// Create original token
				originalToken := New(tt.usage)

				// Derive token from user token
				derivedToken, err := FromUserToken(originalToken.User(), tt.usage)
				if err != nil {
					t.Errorf("FromUserToken failed: %v", err)
					return
				}

				// Verify derived token matches original
				if derivedToken.User() != originalToken.User() {
					t.Error("Derived token User should match original")
				}
				if len(derivedToken.Stored()) != len(originalToken.Stored()) {
					t.Error("Derived token Stored length should match original")
				}
				for i := range derivedToken.Stored() {
					if derivedToken.Stored()[i] != originalToken.Stored()[i] {
						t.Error("Derived token Stored should match original")
						break
					}
				}
				if len(derivedToken.encryption) != len(originalToken.encryption) {
					t.Error("Derived token Encryption key length should match original")
				}
				for i := range derivedToken.encryption {
					if derivedToken.encryption[i] != originalToken.encryption[i] {
						t.Error("Derived token Encryption key should match original")
						break
					}
				}

				// Encrypt with derived token
				encrypted, err := derivedToken.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Errorf("Encrypt with derived token failed: %v", err)
					return
				}

				// Decrypt with original token
				decrypted, err := originalToken.Decrypt(encrypted, tt.additionalData)
				if err != nil {
					t.Errorf("Decrypt with original token failed: %v", err)
					return
				}

				// Verify decrypted data matches original
				if string(decrypted) != tt.plaintext {
					t.Errorf("Decrypted data doesn't match original. Got %q, want %q", string(decrypted), tt.plaintext)
				}

				// Test reverse: encrypt with original, decrypt with derived
				encrypted2, err := originalToken.Encrypt(tt.plaintext, tt.additionalData)
				if err != nil {
					t.Errorf("Encrypt with original token failed: %v", err)
					return
				}

				decrypted2, err := derivedToken.Decrypt(encrypted2, tt.additionalData)
				if err != nil {
					t.Errorf("Decrypt with derived token failed: %v", err)
					return
				}

				if string(decrypted2) != tt.plaintext {
					t.Errorf("Reverse decrypted data doesn't match original. Got %q, want %q", string(decrypted2), tt.plaintext)
				}
			})
		})
	}
}

// TestUsageDomainSeparation tests that different usage values create different tokens
func TestUsageDomainSeparation(t *testing.T) {
	plaintext := "test data"
	additionalData := "grant123"

	// Create tokens with different usage values
	token1 := New("access_token")
	token2 := New("refresh_token")
	token3 := New("authorization_code")

	// Verify that different usage values produce different tokens
	if token1.User() == token2.User() {
		t.Error("Tokens with different usage should have different user tokens")
	}
	if token1.User() == token3.User() {
		t.Error("Tokens with different usage should have different user tokens")
	}
	if token2.User() == token3.User() {
		t.Error("Tokens with different usage should have different user tokens")
	}

	// Test that tokens with different usage cannot decrypt each other's data
	encrypted1, err := token1.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with token1 failed: %v", err)
	}

	encrypted2, err := token2.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with token2 failed: %v", err)
	}

	// Token2 should not be able to decrypt token1's data
	_, err = token2.Decrypt(encrypted1, additionalData)
	if err == nil {
		t.Error("Token2 should not be able to decrypt token1's data")
	}

	// Token1 should not be able to decrypt token2's data
	_, err = token1.Decrypt(encrypted2, additionalData)
	if err == nil {
		t.Error("Token1 should not be able to decrypt token2's data")
	}

	// Test that derived tokens with correct usage can decrypt original data
	derivedToken1, err := FromUserToken(token1.User(), "access_token")
	if err != nil {
		t.Fatalf("FromUserToken failed: %v", err)
	}

	decrypted, err := derivedToken1.Decrypt(encrypted1, additionalData)
	if err != nil {
		t.Errorf("Derived token should be able to decrypt original data: %v", err)
	}
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted data doesn't match original. Got %q, want %q", string(decrypted), plaintext)
	}
}

// TestUsageMismatch tests that using different usage when deriving tokens creates different tokens
func TestUsageMismatch(t *testing.T) {
	// Create a token with one usage
	originalToken := New("access_token")

	// Derive with different usage - this should work but create a different token
	derivedTokenWrong, err := FromUserToken(originalToken.User(), "refresh_token")
	if err != nil {
		t.Errorf("Deriving token with different usage should work: %v", err)
	}

	// Derive with empty usage - this should also work
	derivedTokenEmpty, err := FromUserToken(originalToken.User(), "")
	if err != nil {
		t.Errorf("Deriving token with empty usage should work: %v", err)
	}

	// Verify that different usage creates different tokens
	if derivedTokenWrong.User() != originalToken.User() {
		t.Error("User field should always match regardless of usage")
	}
	if derivedTokenEmpty.User() != originalToken.User() {
		t.Error("User field should always match regardless of usage")
	}

	// But the stored and encryption keys should be different
	if len(derivedTokenWrong.Stored()) == len(originalToken.Stored()) {
		same := true
		for i := range derivedTokenWrong.Stored() {
			if derivedTokenWrong.Stored()[i] != originalToken.Stored()[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Tokens with different usage should have different stored tokens")
		}
	}

	if len(derivedTokenEmpty.Stored()) == len(originalToken.Stored()) {
		same := true
		for i := range derivedTokenEmpty.Stored() {
			if derivedTokenEmpty.Stored()[i] != originalToken.Stored()[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Tokens with empty usage should have different stored tokens")
		}
	}

	// Verify that correct usage works and matches original
	derivedTokenCorrect, err := FromUserToken(originalToken.User(), "access_token")
	if err != nil {
		t.Errorf("Deriving token with correct usage should work: %v", err)
	}

	// Verify derived token matches original
	if derivedTokenCorrect.User() != originalToken.User() {
		t.Error("Derived token User should match original")
	}

	// Test that tokens with different usage cannot decrypt each other's data
	plaintext := "test data"
	additionalData := "grant123"

	encryptedOriginal, err := originalToken.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encrypt with original token failed: %v", err)
	}

	// Wrong usage token should not be able to decrypt original's data
	_, err = derivedTokenWrong.Decrypt(encryptedOriginal, additionalData)
	if err == nil {
		t.Error("Token with wrong usage should not be able to decrypt original's data")
	}

	// Empty usage token should not be able to decrypt original's data
	_, err = derivedTokenEmpty.Decrypt(encryptedOriginal, additionalData)
	if err == nil {
		t.Error("Token with empty usage should not be able to decrypt original's data")
	}

	// Correct usage token should be able to decrypt original's data
	decrypted, err := derivedTokenCorrect.Decrypt(encryptedOriginal, additionalData)
	if err != nil {
		t.Errorf("Token with correct usage should be able to decrypt original's data: %v", err)
	}
	if string(decrypted) != plaintext {
		t.Errorf("Decrypted data doesn't match original. Got %q, want %q", string(decrypted), plaintext)
	}
}

func TestTokenErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		userToken      string
		usage          string
		plaintext      string
		additionalData string
		wantErr        bool
	}{
		{
			name:           "invalid base64 user token",
			userToken:      "invalid-base64!",
			usage:          "access_token",
			plaintext:      "test",
			additionalData: "grant",
			wantErr:        true,
		},
		{
			name:           "valid user token",
			userToken:      New("access_token").User(),
			usage:          "access_token",
			plaintext:      "test",
			additionalData: "grant",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromUserToken(tt.userToken, tt.usage)
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
	// Create a valid token
	token := New("access_token")
	plaintext := "test data"
	additionalData := "grant123"

	// Encrypt some data
	encrypted, err := token.Encrypt(plaintext, additionalData)
	if err != nil {
		t.Fatalf("Setup encryption failed: %v", err)
	}

	tests := []struct {
		name           string
		ciphertext     []byte
		additionalData string
		wantErr        bool
	}{
		{
			name:           "wrong additional data",
			ciphertext:     encrypted,
			additionalData: "wrong-grant",
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
			_, err := token.Decrypt(tt.ciphertext, tt.additionalData)
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
	// Test that the same user token always produces the same derived token
	originalToken := New("access_token")

	token1, err := FromUserToken(originalToken.User(), "access_token")
	if err != nil {
		t.Fatalf("FromUserToken failed: %v", err)
	}

	token2, err := FromUserToken(originalToken.User(), "access_token")
	if err != nil {
		t.Fatalf("FromUserToken failed: %v", err)
	}

	// Check that both derived tokens are identical
	if token1.User() != token2.User() {
		t.Error("User field should be identical")
	}
	if len(token1.Stored()) != len(token2.Stored()) {
		t.Error("Stored field lengths should be identical")
	}
	for i := range token1.Stored() {
		if token1.Stored()[i] != token2.Stored()[i] {
			t.Error("Stored fields should be identical")
			break
		}
	}
	if len(token1.encryption) != len(token2.encryption) {
		t.Error("Encryption key lengths should be identical")
	}
	for i := range token1.encryption {
		if token1.encryption[i] != token2.encryption[i] {
			t.Error("Encryption keys should be identical")
			break
		}
	}

	// Test that different tokens produce different results
	token3 := New("access_token")
	if token1.User() == token3.User() {
		t.Error("Different tokens should have different user tokens")
	}
	if len(token1.Stored()) == len(token3.Stored()) {
		// Check if stored tokens are actually different
		same := true
		for i := range token1.Stored() {
			if token1.Stored()[i] != token3.Stored()[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Different tokens should have different stored tokens")
		}
	}
}
