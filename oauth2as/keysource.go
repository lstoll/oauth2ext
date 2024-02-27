package oidc

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/keyset"
)

var _ KeysetSource = (*StaticKeysource)(nil)

type StaticKeysource struct {
	handle *keyset.Handle
}

func NewStaticKeysource(handle *keyset.Handle) *StaticKeysource {
	return &StaticKeysource{
		handle: handle,
	}
}

func (s *StaticKeysource) PublicHandle(_ context.Context) (*keyset.Handle, error) {
	return s.handle, nil
}
