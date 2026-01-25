package tpmsecrets

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/tink"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
)

// TPMCredentialCache implements tokencache.CredentialCache using TPM sealing via Tink KMS Envelope.
type TPMCredentialCache struct {
	Dir string
}

func (c *TPMCredentialCache) Available() bool {
	rwc, err := openTPM()
	if err == nil {
		closeTPM(rwc)
		return true
	}
	return false
}

func (c *TPMCredentialCache) getAEAD() tink.AEAD {
	// Create the KEK AEAD backed by TPM
	kekAEAD := &tpmAEAD{}

	// Create the Envelope AEAD
	// We use AES256GCM for the DEK
	dekTemplate := aead.AES256GCMKeyTemplate()
	return aead.NewKMSEnvelopeAEAD2(dekTemplate, kekAEAD)
}

func (c *TPMCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	dataPath := filepath.Join(c.Dir, cacheDataFile)
	encData, err := readBlob(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	envAEAD := c.getAEAD()

	plaintext, err := envAEAD.Decrypt(encData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

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
	envAEAD := c.getAEAD()

	// Read existing data to merge
	var tokens map[string]*oidc.TokenWithID
	dataPath := filepath.Join(c.Dir, cacheDataFile)
	encData, err := readBlob(dataPath)
	if err == nil {
		if plaintext, err := envAEAD.Decrypt(encData, nil); err == nil {
			if err := json.Unmarshal(plaintext, &tokens); err != nil {
				// assume it's empty
				tokens = nil
			}
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

	ciphertext, err := envAEAD.Encrypt(newData, nil)
	if err != nil {
		return err
	}

	return writeBlob(dataPath, ciphertext)
}

func (c *TPMCredentialCache) cacheKey(issuer, key string) string {
	return fmt.Sprintf("%s;%s", issuer, key)
}
