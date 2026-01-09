package token

import (
	"bytes"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var _ tink.AEAD = (*DEKHandle)(nil)

// DEKHandle represents a decrypted data encryption key from a token. It can be
// used to decrypt data, and return an updated encrypted DEK for a new token
// without exposing the plaintext DEK.
type DEKHandle struct {
	kh    *keyset.Handle
	usage Usage
}

func (d *DEKHandle) Decrypt(ciphertext []byte, additionalData []byte) ([]byte, error) {
	a, err := aead.New(d.kh)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %w", err)
	}
	return a.Decrypt(ciphertext, additionalData)
}

func (d *DEKHandle) Encrypt(plaintext []byte, additionalData []byte) ([]byte, error) {
	a, err := aead.New(d.kh)
	if err != nil {
		return nil, fmt.Errorf("failed to get AEAD primitive: %w", err)
	}
	return a.Encrypt(plaintext, additionalData)
}

// EncryptDEKToToken encrypts the DEK to a new token, returning the new token's
// encrypted DEK.
func (d *DEKHandle) EncryptDEKToToken(t *Token) ([]byte, error) {
	kek, err := newKEK(t.encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEK: %w", err)
	}

	buf := new(bytes.Buffer)
	// Write the keyset encrypted with the KEK. This produces an EncryptedKeyset.
	if err := d.kh.Write(keyset.NewBinaryWriter(buf), kek); err != nil {
		return nil, fmt.Errorf("failed to write encrypted keyset: %w", err)
	}

	return buf.Bytes(), nil
}

// GenerateDEK generates a new random DEK.
func GenerateDEK() (*DEKHandle, error) {
	kh, err := keyset.NewHandle(aead.AES256GCMNoPrefixKeyTemplate())
	if err != nil {
		return nil, fmt.Errorf("failed to create keyset handle: %w", err)
	}
	return &DEKHandle{
		kh: kh,
	}, nil
}
