package oidcop

import (
	"testing"

	"github.com/google/uuid"
)

func TestTokens(t *testing.T) {
	sessID := uuid.Must(uuid.NewRandom())

	utok, stok, err := newToken(sessID)
	if err != nil {
		t.Fatal(err)
	}

	// get what we send to the user
	utokstr, err := marshalToken(utok)
	if err != nil {
		t.Fatal(err)
	}

	// parse it back, maje sure they compare
	_, gotTok, err := unmarshalToken(utokstr)
	if err != nil {
		t.Fatal(err)
	}

	eq, err := tokensMatch(gotTok, stok)
	if err != nil {
		t.Fatal(err)
	}
	if !eq {
		t.Error("want: tokens to be equal, got not equal")
	}

	utok2, _, err := newToken(sessID)
	if err != nil {
		t.Fatal(err)
	}

	eq, err = tokensMatch(utok2.Token, stok)
	if err != nil {
		t.Fatal(err)
	}
	if eq {
		t.Error("want: tokens to not be equal, got equal")
	}
}
