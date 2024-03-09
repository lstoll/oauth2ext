package oidc

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

// IDToken extracts the ID token from the given oauth2 Token
func IDToken(tok *oauth2.Token) (string, bool) {
	idt, ok := tok.Extra("id_token").(string)
	return idt, ok
}

// TokenWithID reconstructs the oauth2 token, with the ID token added. This
// exists because the serialized form of the oauth2 token does not contain the
// extra/ID token info, so this safely allows a token to be stored and t
func TokenWithID(tok *oauth2.Token, idToken string) *oauth2.Token {
	return nil
}

// MarshaledToken is a wrapper for an oauth2 token, that allows the ID Token to
// be serialized as well if present. This is used when a token needs to be
// saved/restored.
type MarshaledToken struct {
	*oauth2.Token
}

// marshaledToken is our internal state we serialize/deserialize from,
// so we can avoid exposing the ID token directly and in conflict with the
type marshaledToken struct {
	*oauth2.Token
	IDToken string `json:"id_token,omitempty"`
}

func (t *MarshaledToken) UnmarshalJSON(b []byte) error {
	var mt marshaledToken
	if err := json.Unmarshal(b, &mt); err != nil {
		return err
	}
	if t == nil {
		nt := new(MarshaledToken)
		*t = *nt
	}
	t.Token = mt.Token
	if mt.IDToken != "" {
		t.Token = t.Token.WithExtra(map[string]any{
			"id_token": mt.IDToken,
		})
	}
	return nil
}

func (t MarshaledToken) MarshalJSON() ([]byte, error) {
	idt, _ := IDToken(t.Token)
	mt := marshaledToken{
		Token:   t.Token,
		IDToken: idt,
	}

	return json.Marshal(mt)
}
