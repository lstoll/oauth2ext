package tpmsecrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
)

// TPMCredentialCache implements tokencache.CredentialCache using a TPM-sealed
// data key and AES-256-GCM envelope encryption.
type TPMCredentialCache struct {
	Dir string

	sealer keySealer
}

func (c *TPMCredentialCache) keySealer() keySealer {
	if c.sealer != nil {
		return c.sealer
	}
	return tpmKeySealer{}
}

func (c *TPMCredentialCache) Available() bool {
	rwc, err := openTPM()
	if err == nil {
		closeTPM(rwc)
		return true
	}
	return false
}

func (c *TPMCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	dataPath := filepath.Join(c.Dir, cacheDataFile)
	encData, err := readCredentialCache(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	plaintext, err := decryptCredentialCache(c.keySealer(), encData)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	defer clear(plaintext)

	// Parse
	var tokens map[string]*oidc.TokenWithID
	if err := json.Unmarshal(plaintext, &tokens); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	cacheKey := c.cacheKey(issuer, key)
	if t, ok := tokens[cacheKey]; ok {
		return t.Token, nil
	}

	return nil, nil
}

func (c *TPMCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	// Read existing data to merge
	var tokens map[string]*oidc.TokenWithID
	dataPath := filepath.Join(c.Dir, cacheDataFile)
	encData, err := readCredentialCache(dataPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading existing credential cache: %w", err)
	}
	if err == nil {
		plaintext, err := decryptCredentialCache(c.keySealer(), encData)
		if err != nil {
			return fmt.Errorf("decrypting existing credential cache: %w", err)
		}
		decodeErr := json.Unmarshal(plaintext, &tokens)
		clear(plaintext)
		if decodeErr != nil {
			return fmt.Errorf("decoding existing credential cache: %w", decodeErr)
		}
	}
	if tokens == nil {
		tokens = make(map[string]*oidc.TokenWithID)
	}

	// Update
	tokens[c.cacheKey(issuer, key)] = &oidc.TokenWithID{Token: token}

	newData, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	defer clear(newData)

	ciphertext, err := encryptCredentialCache(c.keySealer(), newData)
	if err != nil {
		return err
	}

	return writeBlob(dataPath, ciphertext)
}

func (c *TPMCredentialCache) cacheKey(issuer, key string) string {
	context := make([]byte, 0, 16+len(issuer)+len(key))
	context = binary.BigEndian.AppendUint64(context, uint64(len(issuer)))
	context = append(context, issuer...)
	context = binary.BigEndian.AppendUint64(context, uint64(len(key)))
	context = append(context, key...)
	digest := sha256.Sum256(context)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func readCredentialCache(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCacheEnvelopeSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCacheEnvelopeSize {
		return nil, fmt.Errorf("TPM credential cache is too large")
	}
	return data, nil
}
