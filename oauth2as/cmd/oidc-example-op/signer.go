package main

import (
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func mustInitKeyset() (privHandle *keyset.Handle, pubHandle *keyset.Handle) {
	h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		panic(err)
	}
	ph, err := h.Public()
	if err != nil {
		panic(err)
	}

	return h, ph
}
