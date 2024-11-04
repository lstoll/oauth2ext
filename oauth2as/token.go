package oidcop

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oidc"
	corev1 "github.com/lstoll/oidcop/proto/core/v1"
	"github.com/lstoll/oidcop/storage"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/proto"
)

const (
	tokenLen = 32
)

// newToken generates a fresh token, from random data. The user and stored
// states are returned.
func newToken(id uuid.UUID) (_ *corev1.UserToken, serverPart []byte, _ error) {
	b := make([]byte, tokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, fmt.Errorf("error reading random data: %w", err)
	}

	bc, err := bcrypt.GenerateFromPassword(b, bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	ut := &corev1.UserToken{
		Token:     b,
		SessionId: id.String(), // TODO - re-work proto, make this proper
	}

	return ut, bc, nil
}

// tokensMatch compares a deserialized user token, and it's corresponding stored
// token. if the user token value hashes to the same value on the server.
func tokensMatch(user []byte, stored []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(stored, user)
	if err == nil {
		// no error in comparison, they match
		return true, nil
	} else if err == bcrypt.ErrMismatchedHashAndPassword {
		// they do not match, this isn't an error per se.
		return false, nil
	}
	return false, fmt.Errorf("failed comparing tokens: %w", err)
}

// marshalToken returns a user-friendly version of the token. This is the base64
// serialized marshaled proto
func marshalToken(user *corev1.UserToken) (string, error) {
	b, err := proto.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("couldn't marshal user token to proto: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func unmarshalToken(tok string) (id uuid.UUID, b []byte, _ error) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("base64 decode of token failed: %w", err)
	}
	ut := &corev1.UserToken{}
	if err := proto.Unmarshal(b, ut); err != nil {
		return uuid.Nil, nil, fmt.Errorf("proto decoding of token failed: %w", err)
	}
	uid, err := uuid.Parse(ut.SessionId)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("%s is not a UUID", ut.SessionId)
	}
	return uid, ut.Token, err
}

func (o *OIDC) buildIDAccessTokens(auth *storage.Authorization, identity Identity, extraAccessClaims map[string]any, idExp, atExp time.Time) (id *jwt.RawJWT, access *jwt.RawJWT, _ error) {
	idc := oidc.IDClaims{
		Issuer:   o.issuer,
		Subject:  auth.Subject,
		Expiry:   oidc.UnixTime(idExp.Unix()),
		Audience: oidc.StrOrSlice{auth.ClientID},
		ACR:      auth.ACR,
		AMR:      auth.AMR,
		IssuedAt: oidc.UnixTime(o.now().Unix()),
		AuthTime: oidc.UnixTime(auth.AuthenticatedAt.Unix()),
		Nonce:    auth.Nonce,
	}
	if slices.Contains(auth.Scopes, oidc.ScopeEmail) {
		// TODO - fill
	}
	if slices.Contains(auth.Scopes, oidc.ScopeProfile) {
		// TODO - fill
	}
	idjwt, err := idc.ToJWT(identity.ExtraClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("creating identity token jwt: %w", err)
	}

	ac := oidc.AccessTokenClaims{
		Issuer:   o.issuer,
		Subject:  auth.Subject,
		ClientID: auth.ClientID,
		Expiry:   oidc.UnixTime(atExp.Unix()),
		// TODO - what do we actually want to do here. Is this going to be just
		// an identity server, or do we actually want to extend to access? For
		// now, just make it for the issuer and verify that on userinfo.
		Audience: oidc.StrOrSlice{o.issuer},
		ACR:      auth.ACR,
		AMR:      auth.AMR,
		IssuedAt: oidc.UnixTime(o.now().Unix()),
		AuthTime: oidc.UnixTime(auth.AuthenticatedAt.Unix()),
		JWTID:    uuid.Must(uuid.NewRandom()).String(),
		// TODO - groups/roles etc? Or are these just "extra"
	}
	acjwt, err := ac.ToJWT(extraAccessClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("creating access token jwt: %w", err)
	}

	return idjwt, acjwt, nil
}
