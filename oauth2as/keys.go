package oauth2as

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

// HandleFn is used to get a tink handle for a keyset, when it is needed.
type HandleFn func(context.Context) (*keyset.Handle, error)

// StaticHandleFn is a convenience method to create a HandleFn from a fixed
// keyset handle.
func StaticHandleFn(h *keyset.Handle) HandleFn {
	return HandleFn(func(context.Context) (*keyset.Handle, error) { return h, nil })
}

// SigningAlg represents supported JWT signing algorithms
type SigningAlg string

const (
	SigningAlgRS256 = "RS256"
	SigningAlgES256 = "ES256"
)

func (s SigningAlg) Template() *tinkpb.KeyTemplate {
	switch s {
	case SigningAlgRS256:
		return jwt.RS256_2048_F4_Key_Template()
	case SigningAlgES256:
		return jwt.ES256Template()
	default:
		panic(fmt.Sprintf("invalid signing alg %s", s))
	}
}

type AlgKeysets interface {
	HandleFor(alg SigningAlg) (*keyset.Handle, error)
	SupportedAlgorithms() []SigningAlg
}

type staticAlgKeysets struct {
	alg SigningAlg
	h   *keyset.Handle
}

func (s *staticAlgKeysets) SupportedAlgorithms() []SigningAlg {
	return []SigningAlg{s.alg}
}

func (s *staticAlgKeysets) HandleFor(alg SigningAlg) (*keyset.Handle, error) {
	if alg != s.alg {
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
	return s.h, nil
}

func NewSingleAlgKeysets(alg SigningAlg, h *keyset.Handle) AlgKeysets {
	return &staticAlgKeysets{alg: alg, h: h}
}

// pubHandle returns a public handle that contains the sum of all public keys
// for all supported algorithms.
//
// TODO - would be nice to find a better way, or have the discovery handler just
// take a JWKS as well.
type pubHandle struct {
	h AlgKeysets
}

func (p *pubHandle) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	mergejwksm := map[string]any{
		"keys": []any{},
	}

	for _, alg := range p.h.SupportedAlgorithms() {
		h, err := p.h.HandleFor(alg)
		if err != nil {
			return nil, fmt.Errorf("getting handle for %s: %w", alg, err)
		}

		pub, err := h.Public()
		if err != nil {
			return nil, fmt.Errorf("getting public handle for %s: %w", alg, err)
		}

		jwks, err := jwt.JWKSetFromPublicKeysetHandle(pub)
		if err != nil {
			return nil, fmt.Errorf("getting JWKS for %s: %w", alg, err)
		}

		jwksm := make(map[string]any)
		if err := json.Unmarshal(jwks, &jwksm); err != nil {
			return nil, fmt.Errorf("unmarshalling JWKS for %s: %w", alg, err)
		}

		for _, k := range jwksm["keys"].([]any) {
			mergejwksm["keys"] = append(mergejwksm["keys"].([]any), k)
		}
	}

	mergejwks, err := json.Marshal(mergejwksm)
	if err != nil {
		return nil, fmt.Errorf("marshalling merged JWKS: %w", err)
	}

	mergeh, err := jwt.JWKSetToPublicKeysetHandle(mergejwks)
	if err != nil {
		return nil, fmt.Errorf("converting merged JWKS to public handle: %w", err)
	}

	return mergeh, nil
}
