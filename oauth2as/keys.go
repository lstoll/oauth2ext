package oauth2as

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lstoll/oauth2ext/jwt"
	tinkjwt "github.com/tink-crypto/tink-go/v2/jwt"
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
		return tinkjwt.RS256_2048_F4_Key_Template()
	case SigningAlgES256:
		return tinkjwt.ES256Template()
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

var _ jwt.PublicKeyset = (*pubHandle)(nil)

type pubHandle struct {
	h AlgKeysets
}

func (p *pubHandle) GetKeysByKID(ctx context.Context, kid string) ([]jwt.PublicKey, error) {
	sks, err := p.buildStaticKeyset(ctx)
	if err != nil {
		return nil, err
	}
	return sks.GetKeysByKID(ctx, kid)
}

func (p *pubHandle) GetKeys(ctx context.Context) ([]jwt.PublicKey, error) {
	sks, err := p.buildStaticKeyset(ctx)
	if err != nil {
		return nil, err
	}
	return sks.GetKeys(ctx)
}

func (p *pubHandle) buildStaticKeyset(_ context.Context) (*jwt.StaticKeyset, error) {
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

		jwks, err := tinkjwt.JWKSetFromPublicKeysetHandle(pub)
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

	return jwt.NewStaticKeysetFromJWKS(mergejwks)
}
