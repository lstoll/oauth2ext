//go:build darwin && cgo

package platformsecrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal/keychain"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/tokencache"
)

func init() {
	platformCaches = append(platformCaches, &KeychainCredentialCache{})
}

type keychainCredentialAccount struct {
	Issuer string `json:"issuer,omitzero"`
	Key    string `json:"key,omitzero"`

	// TODO - reconsider the interface for a token cache to include more fields?
}

// KeychainCredentialCache uses the macOS keychain to store items. Items are
// keyed by the binary and issuer that they are for. It is intended for
// short/ephemeral caching, entries created via different executables will be
// removed rather than requiring the executable to be signed, or user input.
type KeychainCredentialCache struct {
	// Service is the name of the service we use to store keychain items.
	// If not set, defaults to clitoken.<binary-name>
	Service string
}

var _ tokencache.CredentialCache = &KeychainCredentialCache{}

func (k *KeychainCredentialCache) Get(issuer, key string) (*oauth2.Token, error) {
	binaryID, err := keychain.GetBinaryIdentity()
	if err != nil {
		return nil, fmt.Errorf("getting binary identity: %w", err)
	}

	accountB, err := json.Marshal(keychainCredentialAccount{
		Issuer: issuer,
		Key:    key,
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling key: %w", err)
	}

	service, err := k.serviceName()
	if err != nil {
		return nil, fmt.Errorf("getting service name: %w", err)
	}

	attrs, err := keychain.GetGenericPasswordAttributes(keychain.GenericPasswordQuery{
		Service: service,
		Account: string(accountB),
	})
	if err != nil {
		var kcErr *keychain.Error
		if errors.As(err, &kcErr) {
			if kcErr.Code == keychain.KeychainErrorCodeItemNotFound {
				// not found, just return nil
				return nil, nil
			}
		}
		return nil, fmt.Errorf("getting generic password attributes: %w", err)
	}

	if !bytes.Equal(attrs.GenericAttributes, []byte(binaryID)) {
		// does not match this binary, delete and treat as not found
		_ = keychain.DeleteGenericPassword(keychain.GenericPasswordQuery{
			Service: service,
			Account: string(accountB),
		})
		return nil, nil
	}

	tokenB, err := keychain.GetGenericPassword(keychain.GenericPasswordQuery{
		Service: service,
		Account: string(accountB),
	})
	if err != nil {
		return nil, fmt.Errorf("getting generic password: %w", err)
	}

	var token oidc.TokenWithID
	if err := json.Unmarshal(tokenB, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return token.Token, nil
}

func (k *KeychainCredentialCache) Set(issuer, key string, token *oauth2.Token) error {
	b, err := json.Marshal(oidc.TokenWithID{Token: token})
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	service, err := k.serviceName()
	if err != nil {
		return fmt.Errorf("getting service name: %w", err)
	}

	binaryID, err := keychain.GetBinaryIdentity()
	if err != nil {
		return fmt.Errorf("getting binary identity: %w", err)
	}

	accountB, err := json.Marshal(keychainCredentialAccount{
		Issuer: issuer,
		Key:    key,
	})
	if err != nil {
		return fmt.Errorf("marshalling account: %w", err)
	}

	// delete any existing item with this account
	if err := keychain.DeleteGenericPassword(keychain.GenericPasswordQuery{
		Service: service,
		Account: string(accountB),
	}); err != nil {
		var kcErr *keychain.Error
		if !errors.As(err, &kcErr) || kcErr.Code != keychain.KeychainErrorCodeItemNotFound {
			return fmt.Errorf("deleting existing item: %w", err)
		}
	}

	if err := keychain.CreateGenericPassword(keychain.GenericPassword{
		Service:           service,
		Account:           string(accountB),
		Label:             fmt.Sprintf("%s: %s (%s)", service, issuer, key),
		GenericAttributes: []byte(binaryID),
		Value:             b,
	}); err != nil {
		return fmt.Errorf("saving credential to keychain: %w", err)
	}

	return nil
}

// Delete deletes the item for the given issuer and key, if it exists.
func (k *KeychainCredentialCache) Delete(issuer, key string) error {
	service, err := k.serviceName()
	if err != nil {
		return fmt.Errorf("getting service name: %w", err)
	}

	accountB, err := json.Marshal(keychainCredentialAccount{
		Issuer: issuer,
		Key:    key,
	})
	if err != nil {
		return fmt.Errorf("marshalling account: %w", err)
	}

	err = keychain.DeleteGenericPassword(keychain.GenericPasswordQuery{
		Service: service,
		Account: string(accountB),
	})
	if err != nil {
		var kcErr *keychain.Error
		if errors.As(err, &kcErr) {
			if kcErr.Code == keychain.KeychainErrorCodeItemNotFound {
				return nil
			}
		}
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
	service, err := k.serviceName()
	if err != nil {
		return nil, fmt.Errorf("getting service name: %w", err)
	}

	binaryID, err := keychain.GetBinaryIdentity()
	if err != nil {
		return nil, fmt.Errorf("getting binary identity: %w", err)
	}

	items, err := keychain.ListGenericPasswords(keychain.GenericPasswordQuery{
		Service: service,
	})
	if err != nil {
		var kcErr *keychain.Error
		if errors.As(err, &kcErr) {
			if kcErr.Code == keychain.KeychainErrorCodeItemNotFound {
				// no items found, just return empty list
				return nil, nil
			}
		}
		return nil, fmt.Errorf("listing items from keychain: %w", err)
	}

	listItems := make([]KeychainListItem, 0, len(items))

	for _, item := range items {
		var account keychainCredentialAccount
		if err := json.Unmarshal([]byte(item.Account), &account); err != nil {
			return nil, fmt.Errorf("unmarshalling account: %w", err)
		}
		// skip items that we couldn't read
		if !bytes.Equal(item.GenericAttributes, []byte(binaryID)) {
			continue
		}
		listItems = append(listItems, KeychainListItem(account))
	}

	return listItems, nil
}

// DeleteAll deletes all items in the keychain for this service.
func (k *KeychainCredentialCache) DeleteAll() error {
	service, err := k.serviceName()
	if err != nil {
		return fmt.Errorf("getting service name: %w", err)
	}

	if err := keychain.DeleteGenericPassword(keychain.GenericPasswordQuery{
		Service: service,
	}); err != nil {
		var kcErr *keychain.Error
		if errors.As(err, &kcErr) {
			if kcErr.Code == keychain.KeychainErrorCodeItemNotFound {
				return nil
			}
		}
		return fmt.Errorf("deleting all items from keychain for service %q: %w", service, err)
	}

	return nil
}

func (k *KeychainCredentialCache) Available() bool {
	// should always be this, but check anyway
	return runtime.GOOS == "darwin"
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
