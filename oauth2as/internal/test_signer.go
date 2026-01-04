package internal

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type TestSigner struct {
	defaultAlg string
	handles    map[string]*keyset.Handle
	handlesMu  sync.Mutex
}

func NewTestSigner(t testing.TB, algs ...string) *TestSigner {
	if len(algs) == 0 {
		algs = []string{"ES256"}
	}
	ts := &TestSigner{
		defaultAlg: algs[0],
		handles:    make(map[string]*keyset.Handle, len(algs)),
	}
	for _, alg := range algs {
		switch alg {
		case "ES256":
			handle, err := keyset.NewHandle(jwt.ES256Template())
			if err != nil {
				t.Fatal(err)
			}
			ts.handles[alg] = handle
		case "RS256":
			handle, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
			if err != nil {
				t.Fatal(err)
			}
			ts.handles[alg] = handle
		default:
			t.Fatalf("unsupported algorithm: %s", alg)
		}
	}

	return ts
}

func (t *TestSigner) SignAndEncode(rawJWT *jwt.RawJWT) (string, error) {
	return t.SignAndEncodeForAlgorithm(t.defaultAlg, rawJWT)
}

func (t *TestSigner) SignAndEncodeForAlgorithm(alg string, rawJWT *jwt.RawJWT) (string, error) {
	t.handlesMu.Lock()
	defer t.handlesMu.Unlock()

	handle, ok := t.handles[alg]
	if !ok {
		return "", fmt.Errorf("key not found for algorithm: %s", alg)
	}
	signer, err := jwt.NewSigner(handle)
	if err != nil {
		return "", err
	}

	return signer.SignAndEncode(rawJWT)
}

func (t *TestSigner) VerifyAndDecode(compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	merged, err := t.mergedPublicHandle()
	if err != nil {
		return nil, fmt.Errorf("merging handles: %w", err)
	}
	verifier, err := jwt.NewVerifier(merged)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}
	return verifier.VerifyAndDecode(compact, validator)
}

func (t *TestSigner) JWKS(ctx context.Context) ([]byte, error) {
	merged, err := t.mergedPublicHandle()
	if err != nil {
		return nil, fmt.Errorf("merging handles: %w", err)
	}

	return jwt.JWKSetFromPublicKeysetHandle(merged)
}

func (t *TestSigner) mergedPublicHandle() (*keyset.Handle, error) {
	t.handlesMu.Lock()
	defer t.handlesMu.Unlock()

	var handles []*keyset.Handle
	for _, h := range t.handles {
		pubh, err := h.Public()
		if err != nil {
			return nil, fmt.Errorf("getting public handle: %w", err)
		}
		handles = append(handles, pubh)
	}
	return mergeHandles(handles...)
}

func mergeHandles(handles ...*keyset.Handle) (*keyset.Handle, error) {
	mgr := keyset.NewManager()
	var lastKid uint32
	for _, handle := range handles {
		for i := range handle.Len() {
			e, err := handle.Entry(i)
			if err != nil {
				return nil, err
			}
			if _, err := mgr.AddKey(e.Key()); err != nil {
				return nil, fmt.Errorf("adding key: %w", err)
			}
			lastKid = e.KeyID()
		}
	}
	// we're required to have a primary, even though we only use it for signing.
	// Just pick one.
	if err := mgr.SetPrimary(lastKid); err != nil {
		return nil, fmt.Errorf("setting primary: %w", err)
	}
	h, err := mgr.Handle()
	if err != nil {
		return nil, fmt.Errorf("getting handle: %w", err)
	}
	return h, nil
}
