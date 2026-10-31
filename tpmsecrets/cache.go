package tpmsecrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/tokencache"
)

// TPMCredentialCache implements tokencache.Store using a TPM-sealed data key and
// AES-256-GCM envelope encryption. DPoP keys are per-credential TPM keys whose
// wrapped blobs are stored in the cache next to the token.
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

type cacheEntry struct {
	Token   *oidc.TokenWithID `json:"token"`
	DPoPKey []byte            `json:"dpop_key,omitzero"`
}

var _ tokencache.Store = (*TPMCredentialCache)(nil)

// Get returns the credential for the issuer and key. It does not take the
// lock, as the cache file is replaced atomically.
func (c *TPMCredentialCache) Get(issuer, key string) (*tokencache.Credential, error) {
	entries, err := c.load()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	e, ok := entries[c.cacheKey(issuer, key)]
	if !ok || e == nil || e.Token == nil {
		return nil, nil
	}
	return &tokencache.Credential{Token: e.Token.Token, DPoPKey: e.DPoPKey}, nil
}

func (c *TPMCredentialCache) Set(issuer, key string, cred *tokencache.Credential) error {
	if cred == nil || cred.Token == nil {
		return errors.New("credential must have a token")
	}
	if err := os.MkdirAll(c.Dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.Dir, cacheLockFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("opening cache lock: %w", err)
	}
	defer lock.Close()
	unlock, err := lockFile(lock)
	if err != nil {
		return fmt.Errorf("locking cache: %w", err)
	}
	defer unlock()

	entries, err := c.load()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading existing credential cache: %w", err)
	}
	if entries == nil {
		entries = make(map[string]*cacheEntry)
	}
	entries[c.cacheKey(issuer, key)] = &cacheEntry{Token: &oidc.TokenWithID{Token: cred.Token}, DPoPKey: cred.DPoPKey}

	newData, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	defer clear(newData)

	ciphertext, err := encryptCredentialCache(c.keySealer(), newData)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.Dir, cacheDataFile), ciphertext)
}

// load reads and decrypts the cache file. A missing file returns an error
// satisfying os.IsNotExist.
func (c *TPMCredentialCache) load() (map[string]*cacheEntry, error) {
	encData, err := readCredentialCache(filepath.Join(c.Dir, cacheDataFile))
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptCredentialCache(c.keySealer(), encData)
	if err != nil {
		return nil, fmt.Errorf("decrypting credential cache: %w", err)
	}
	defer clear(plaintext)
	var entries map[string]*cacheEntry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("decoding credential cache: %w", err)
	}
	return entries, nil
}

// writeFileAtomic writes data to a temp file in the same directory, then
// renames it over path.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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
