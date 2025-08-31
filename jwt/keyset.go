package jwt

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type SigningAlg string

const (
	SigningAlgRS256 SigningAlg = "RS256"
	SigningAlgES256 SigningAlg = "ES256"
)

type PublicKey struct {
	KeyID string
	Alg   SigningAlg
	Key   crypto.PublicKey
}

type PublicKeyset interface {
	GetKeysByKID(ctx context.Context, kid string) ([]PublicKey, error)
	GetKeys(ctx context.Context) ([]PublicKey, error)
}

type StaticKeyset struct {
	Keys []PublicKey
}

func NewStaticKeysetFromJWKS(jwksb []byte) (*StaticKeyset, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksb, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshalling JWKS: %w", err)
	}

	keys := make([]PublicKey, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		keys = append(keys, PublicKey{KeyID: key.KeyID, Alg: SigningAlg(key.Algorithm), Key: key.Key})
	}
	return &StaticKeyset{Keys: keys}, nil
}

func (s *StaticKeyset) GetKeysByKID(ctx context.Context, kid string) ([]PublicKey, error) {
	var keys []PublicKey
	for _, key := range s.Keys {
		if key.KeyID == kid {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (s *StaticKeyset) GetKeys(ctx context.Context) ([]PublicKey, error) {
	return s.Keys, nil
}

const DefaultHTTPJWKSCacheDuration = 10 * time.Minute

type HTTPJWKSKeyset struct {
	URL           string
	CacheDuration time.Duration
	HTTPClient    *http.Client

	lastKeyset         *StaticKeyset
	lastKeysetFetched  time.Time
	lastKeysetCacheFor time.Duration
	cacheMu            sync.Mutex
}

func (k *HTTPJWKSKeyset) GetKeysByKID(ctx context.Context, kid string) ([]PublicKey, error) {
	if err := k.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}

	return k.lastKeyset.GetKeysByKID(ctx, kid)
}

func (k *HTTPJWKSKeyset) GetKeys(ctx context.Context) ([]PublicKey, error) {
	if err := k.refreshIfNeeded(ctx); err != nil {
		return nil, err
	}

	return k.lastKeyset.GetKeys(ctx)
}

var validJWKSContentTypes = []string{
	"application/json",
	"application/jwk-set+json",
}

func (k *HTTPJWKSKeyset) refreshIfNeeded(ctx context.Context) error {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()

	cacheFor := k.lastKeysetCacheFor
	if cacheFor == 0 {
		cacheFor = DefaultHTTPJWKSCacheDuration
	}

	if time.Since(k.lastKeysetFetched) < cacheFor {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", k.URL, err)
	}
	req = req.WithContext(ctx)
	hc := k.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get keys from %s: %v", k.URL, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
	}
	if !slices.Contains(validJWKSContentTypes, res.Header.Get("Content-Type")) {
		return fmt.Errorf("expected content type %s, got: %s", strings.Join(validJWKSContentTypes, ", "), res.Header.Get("Content-Type"))
	}
	jwksb, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksb, &jwks); err != nil {
		return fmt.Errorf("unmarshalling JWKS: %w", err)
	}

	k.lastKeyset, err = NewStaticKeysetFromJWKS(jwksb)
	if err != nil {
		return fmt.Errorf("creating static keyset from JWKS: %w", err)
	}
	k.lastKeysetFetched = time.Now()

	return nil
}
