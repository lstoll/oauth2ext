//go:build darwin

package keychainsecrets

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"lds.li/keychain"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/tokencache"
)

type keychainCredentialAccount struct {
	Issuer string `json:"issuer,omitzero"`
	Key    string `json:"key,omitzero"`
}

// keychainCredentialValue is the stored value for an entry.
type keychainCredentialValue struct {
	Token   *oidc.TokenWithID `json:"token"`
	DPoPKey []byte            `json:"dpop_key,omitzero"`
}

// KeychainCredentialCache uses the macOS keychain to store items. Items are
// keyed by the binary and issuer that they are for. It is intended for
// short/ephemeral caching, entries created via different executables will be
// removed rather than requiring the executable to be signed, or user input.
//
// DPoP keys are Secure Enclave keys created per login. The device-bound key
// blob is stored in the keychain entry alongside the token.
type KeychainCredentialCache struct {
	// Service is the name of the service we use to store keychain items.
	// If not set, defaults to clitoken.<binary-name>
	Service string

	mu    sync.Mutex
	cache *keychain.Cache
}

var _ tokencache.Store = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) kc() (*keychain.Cache, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cache != nil {
		return k.cache, nil
	}
	service, err := k.serviceName()
	if err != nil {
		return nil, fmt.Errorf("getting service name: %w", err)
	}
	c, err := keychain.NewCache(keychain.CacheOptions{Service: service})
	if err != nil {
		return nil, fmt.Errorf("creating keychain cache: %w", err)
	}
	k.cache = c
	return c, nil
}

func accountKey(issuer, key string) (string, error) {
	b, err := json.Marshal(keychainCredentialAccount{Issuer: issuer, Key: key})
	if err != nil {
		return "", fmt.Errorf("marshalling account: %w", err)
	}
	return string(b), nil
}

func (k *KeychainCredentialCache) Get(issuer, key string) (*tokencache.Credential, error) {
	c, err := k.kc()
	if err != nil {
		return nil, err
	}
	acct, err := accountKey(issuer, key)
	if err != nil {
		return nil, err
	}
	b, ok, err := c.Get(acct)
	if err != nil {
		return nil, fmt.Errorf("getting credential from keychain: %w", err)
	}
	if !ok {
		return nil, nil
	}
	var v keychainCredentialValue
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("failed to decode credential: %w", err)
	}
	if v.Token == nil {
		return nil, nil
	}
	return &tokencache.Credential{Token: v.Token.Token, DPoPKey: v.DPoPKey}, nil
}

func (k *KeychainCredentialCache) Set(issuer, key string, cred *tokencache.Credential) error {
	if cred == nil {
		return errors.New("nil credential")
	}
	c, err := k.kc()
	if err != nil {
		return err
	}
	acct, err := accountKey(issuer, key)
	if err != nil {
		return err
	}
	b, err := json.Marshal(keychainCredentialValue{
		Token:   &oidc.TokenWithID{Token: cred.Token},
		DPoPKey: cred.DPoPKey,
	})
	if err != nil {
		return fmt.Errorf("failed to encode credential: %w", err)
	}
	service, err := k.serviceName()
	if err != nil {
		return fmt.Errorf("getting service name: %w", err)
	}
	if err := c.Put(acct, b, fmt.Sprintf("%s: %s (%s)", service, issuer, key)); err != nil {
		return fmt.Errorf("saving credential to keychain: %w", err)
	}
	return nil
}

// Delete deletes the item for the given issuer and key, if it exists.
func (k *KeychainCredentialCache) Delete(issuer, key string) error {
	c, err := k.kc()
	if err != nil {
		return err
	}
	acct, err := accountKey(issuer, key)
	if err != nil {
		return err
	}
	if err := c.Delete(acct); err != nil {
		return fmt.Errorf("deleting credential from keychain: %w", err)
	}
	return nil
}

type KeychainListItem struct {
	Issuer string
	Key    string
}

// List returns all items in the keychain for this service.
func (k *KeychainCredentialCache) List() ([]KeychainListItem, error) {
	c, err := k.kc()
	if err != nil {
		return nil, err
	}
	entries, err := c.List()
	if err != nil {
		return nil, fmt.Errorf("listing items from keychain: %w", err)
	}
	items := make([]KeychainListItem, 0, len(entries))
	for _, e := range entries {
		var account keychainCredentialAccount
		if err := json.Unmarshal([]byte(e.Key), &account); err != nil {
			continue
		}
		items = append(items, KeychainListItem(account))
	}
	return items, nil
}

// DeleteAll deletes all items in the keychain for this service.
func (k *KeychainCredentialCache) DeleteAll() error {
	c, err := k.kc()
	if err != nil {
		return err
	}
	if err := c.Clear(); err != nil {
		return fmt.Errorf("deleting all items from keychain: %w", err)
	}
	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	// should always be this, but check anyway
	return runtime.GOOS == "darwin"
}

// NewDPoPKey creates a Secure Enclave P-256 key. The handle is the key's
// device-bound data representation.
func (k *KeychainCredentialCache) NewDPoPKey() ([]byte, crypto.Signer, error) {
	key, err := keychain.CreateSecureEnclaveKey(keychain.SecureEnclaveKeyOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("creating Secure Enclave key: %w", err)
	}
	return key.DataRepresentation(), key, nil
}

// LoadDPoPKey loads a key from a handle returned by NewDPoPKey.
func (k *KeychainCredentialCache) LoadDPoPKey(handle []byte) (crypto.Signer, error) {
	key, err := keychain.LoadSecureEnclaveKey(handle, keychain.SecureEnclaveLoadOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading Secure Enclave key: %w", err)
	}
	if key.Algorithm() != keychain.SecureEnclaveP256 {
		return nil, fmt.Errorf("unsupported Secure Enclave key algorithm %s", key.Algorithm())
	}
	return key, nil
}

func (k *KeychainCredentialCache) serviceName() (string, error) {
	if k.Service != "" {
		return k.Service, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return "clitoken." + filepath.Base(execPath), nil
}
