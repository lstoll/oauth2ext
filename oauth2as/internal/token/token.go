package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

var (
	// these were generated with salt.go. we use fixed salts to domain separate
	// key derivation from tokens.
	encSalt    = []byte{4, 50, 41, 133, 73, 226, 110, 54, 6, 66, 16, 110, 19, 220, 42, 77, 247, 197, 203, 135, 83, 136, 72, 116, 39, 173, 26, 144, 215, 47, 234, 71}
	storedSalt = []byte{65, 2, 216, 144, 128, 170, 60, 8, 133, 174, 56, 168, 86, 87, 200, 184, 244, 39, 252, 45, 194, 114, 212, 236, 142, 241, 64, 71, 34, 106, 209, 42}

	keyLength = 32
)

// Token represents a single token issued in the system.
type Token struct {
	// User is the value that is exposed to the user.
	user string
	// Stored is the value that should be stored in the datastore. It can be
	// looked up one-way by the user token.
	stored []byte
	// Encryption is an encryption key bound to this token. It can be generated
	// from the user token, but not from the stored token or any other source.
	// Suitable for AES-256.
	encryption []byte
}

// User returns the value that should be exposed and used by the user.
func (t Token) User() string {
	return t.user
}

// Stored returns the value that should be stored in the datastore, for lookups.
func (t Token) Stored() []byte {
	return t.stored
}

// New creates a new token.
func New(usage string) Token {
	var tok = make([]byte, 32)
	if n, err := io.ReadFull(rand.Reader, tok); err != nil || n != 32 {
		panic(fmt.Sprintf("failed to generate random token: %v", err))
	}

	stored, err := hkdf.Key(sha256.New, tok, storedSalt, usage, keyLength)
	if err != nil {
		panic(fmt.Sprintf("failed to generate stored token: %v", err))
	}

	encryption, err := hkdf.Key(sha256.New, tok, encSalt, usage, keyLength)
	if err != nil {
		panic(fmt.Sprintf("failed to generate encryption key: %v", err))
	}

	return Token{
		user:       base64.URLEncoding.EncodeToString(tok),
		stored:     stored,
		encryption: encryption,
	}
}

// FromUserToken creates a Token struct from a user token string.
func FromUserToken(userToken, usage string) (Token, error) {
	user, err := base64.URLEncoding.DecodeString(userToken)
	if err != nil {
		return Token{}, fmt.Errorf("failed to decode user token: %v", err)
	}

	stored, err := hkdf.Key(sha256.New, user, storedSalt, usage, keyLength)
	if err != nil {
		return Token{}, fmt.Errorf("failed to generate stored token: %v", err)
	}

	encryption, err := hkdf.Key(sha256.New, user, encSalt, usage, keyLength)
	if err != nil {
		return Token{}, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return Token{
		user:       userToken,
		stored:     stored,
		encryption: encryption,
	}, nil
}

// Encrypt encrypts the plaintext with this token's encryption key.
func (t *Token) Encrypt(plaintext, additionalData string) ([]byte, error) {
	if len(t.encryption) != keyLength {
		return nil, fmt.Errorf("encryption key is not the correct length")
	}

	block, err := aes.NewCipher(t.encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), []byte(additionalData))

	result := append(nonce, ciphertext...)
	return result, nil
}

// Decrypt decrypts the ciphertext with this token's encryption key.
func (t *Token) Decrypt(ciphertext []byte, additionalData string) ([]byte, error) {
	if len(t.encryption) != keyLength {
		return nil, fmt.Errorf("encryption key is not the correct length")
	}

	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	nonce := ciphertext[:12]
	enc := ciphertext[12:]

	block, err := aes.NewCipher(t.encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	plain, err := aead.Open(nil, nonce, enc, []byte(additionalData))
	if err != nil {
		return nil, fmt.Errorf("failed to open ciphertext: %v", err)
	}
	return plain, nil
}
