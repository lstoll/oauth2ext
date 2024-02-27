package main

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type keysetSource struct {
	h  *keyset.Handle
	ph *keyset.Handle
}

func (k *keysetSource) Handle(_ context.Context) (*keyset.Handle, error) {
	return k.h, nil
}

func (k *keysetSource) PublicHandle(_ context.Context) (*keyset.Handle, error) {
	return k.ph, nil
}

func mustInitKeysetSource() *keysetSource {
	h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		panic(err)
	}
	ph, err := h.Public()
	if err != nil {
		panic(err)
	}

	return &keysetSource{
		h:  h,
		ph: ph,
	}
}
