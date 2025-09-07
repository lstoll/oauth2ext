package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
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
	SigningAlgRS256 SigningAlg = SigningAlg(jose.RS256)
	SigningAlgRS384 SigningAlg = SigningAlg(jose.RS384)
	SigningAlgRS512 SigningAlg = SigningAlg(jose.RS512)
	SigningAlgES256 SigningAlg = SigningAlg(jose.ES256)
	SigningAlgES384 SigningAlg = SigningAlg(jose.ES384)
	SigningAlgES512 SigningAlg = SigningAlg(jose.ES512)
	SigningAlgPS256 SigningAlg = SigningAlg(jose.PS256)
	SigningAlgPS384 SigningAlg = SigningAlg(jose.PS384)
	SigningAlgPS512 SigningAlg = SigningAlg(jose.PS512)
	SigningAlgEdDSA SigningAlg = SigningAlg(jose.EdDSA)
)

type PublicKey struct {
	KeyID string
	Alg   SigningAlg
	Key   crypto.PublicKey
}

// Valid checks if this is a valid public key entry, returning an error
// explaining why if it is not.
func (p *PublicKey) Valid() error {
	if p.Key == nil {
		return fmt.Errorf("key is nil")
	}
	switch k := p.Key.(type) {
	case *rsa.PublicKey:
		if p.Alg != SigningAlgRS256 && p.Alg != SigningAlgRS384 && p.Alg != SigningAlgRS512 &&
			p.Alg != SigningAlgPS256 && p.Alg != SigningAlgPS384 && p.Alg != SigningAlgPS512 {
			return fmt.Errorf("key algorithm is %s, expected a RS/PS variant", p.Alg)
		}
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			if p.Alg != SigningAlgES256 {
				return fmt.Errorf("key algorithm is %s, expected %s", p.Alg, SigningAlgES256)
			}
			return nil
		case elliptic.P384():
			if p.Alg != SigningAlgES384 {
				return fmt.Errorf("key algorithm is %s, expected %s", p.Alg, SigningAlgES384)
			}
			return nil
		case elliptic.P521():
			if p.Alg != SigningAlgES512 {
				return fmt.Errorf("key algorithm is %s, expected %s", p.Alg, SigningAlgES512)
			}
			return nil
		default:
			return fmt.Errorf("unsupported curve: %s", k.Curve)
		}
	case ed25519.PublicKey:
		if p.Alg != SigningAlgEdDSA {
			return fmt.Errorf("key algorithm is %s, expected %s", p.Alg, SigningAlgEdDSA)
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", k)
	}
	// do not add a return here, make sure the switch is exhaustive
}

// PublicKeyset is an interface to retrieve keys for verifying JWTs.
type PublicKeyset interface {
	GetKeysByKID(ctx context.Context, kid string) ([]PublicKey, error)
}

// StaticKeyset implements [PublicKeyset] against a set of fixed keys,
type StaticKeyset struct {
	Keys []PublicKey
}

// NewStaticKeysetFromJWKS creates a [StaticKeyset] from a serialized JWKS.
func NewStaticKeysetFromJWKS(jwksb []byte) (*StaticKeyset, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksb, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshalling JWKS: %w", err)
	}

	keys := make([]PublicKey, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		pk := PublicKey{KeyID: key.KeyID, Alg: SigningAlg(key.Algorithm), Key: key.Key}
		if err := pk.Valid(); err != nil {
			return nil, fmt.Errorf("invalid key %s: %w", key.KeyID, err)
		}
		keys = append(keys, pk)
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

// HTTPJWKSKeyset implements [PublicKeyset] for a JWKS published via HTTP. It
// will cache keys.
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
