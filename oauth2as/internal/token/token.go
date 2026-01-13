package token

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	aeadsubtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinksubtle "github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
)

const o2asPrefix = "o2as"

var (
	// these were generated with salt.go. we use fixed salts to domain separate
	// key derivation from tokens.
	encSalt    = []byte{4, 50, 41, 133, 73, 226, 110, 54, 6, 66, 16, 110, 19, 220, 42, 77, 247, 197, 203, 135, 83, 136, 72, 116, 39, 173, 26, 144, 215, 47, 234, 71}
	storedSalt = []byte{65, 2, 216, 144, 128, 170, 60, 8, 133, 174, 56, 168, 86, 87, 200, 184, 244, 39, 252, 45, 194, 114, 212, 236, 142, 241, 64, 71, 34, 106, 209, 42}

	tokenEncoding = base64.RawURLEncoding
)

type Usage struct {
	// Name is the full name of the usage, mixed in to the key derivation.
	Name string
	// Prefix is used on the user representation of this token.
	Prefix string
}

type ParsedToken struct {
	usage   Usage
	payload *TokenData
	user    []byte
}

// ID returns the ID from the token, to lookup the token in the datastore.
func (p *ParsedToken) ID() string {
	return p.payload.GetTokenId()
}

// Payload returns the payload from the token.
func (p *ParsedToken) Payload() *TokenData {
	return p.payload
}

// ParseUserToken creates a Token struct from a user token string.
// Error messages are intentionally generic to avoid leaking information
// about token structure to potential attackers.
func ParseUserToken(userToken string, usage Usage) (*ParsedToken, error) {
	prefix, encodedProto, ok := strings.Cut(userToken, "_")
	if !ok {
		return nil, errors.New("malformed user token")
	}

	if prefix != o2asPrefix+usage.Prefix {
		return nil, fmt.Errorf("invalid prefix for usage: %s", prefix)
	}

	protoBytes, err := tokenEncoding.DecodeString(encodedProto)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user token: %v", err)
	}

	var td TokenData
	if err := proto.Unmarshal(protoBytes, &td); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user token: %v", err)
	}

	return &ParsedToken{
		usage:   usage,
		payload: &td,
		user:    td.GetSecret(),
	}, nil
}

// Verify verifies the parsed token against the stored value, returning the
// verified token if successful.
func (p *ParsedToken) Verify(usage Usage, storedValue []byte, expectedGrantID, expectedUserID string) (*Token, error) {
	if p.payload.GetGrantId() != expectedGrantID {
		return nil, fmt.Errorf("token grant ID %q does not match expected %q", p.payload.GetGrantId(), expectedGrantID)
	}
	if p.payload.GetUserId() != expectedUserID {
		return nil, fmt.Errorf("token user ID %q does not match expected %q", p.payload.GetUserId(), expectedUserID)
	}

	info := fmt.Sprintf("%s:%s:%s", usage.Name, expectedGrantID, expectedUserID)

	stored, err := hkdf.Key(sha256.New, p.user, storedSalt, info, keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate stored token: %v", err)
	}

	if subtle.ConstantTimeCompare(stored, storedValue) != 1 {
		return nil, errors.New("token does not match stored value")
	}

	encryption, err := hkdf.Key(sha256.New, p.user, encSalt, info, keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return &Token{
		user:       p.user,
		stored:     stored,
		encryption: encryption,
		usage:      usage,
		payload:    p.payload,
	}, nil
}

// Token represents a token in it's active state.
type Token struct {
	usage   Usage
	payload *TokenData
	// User is the value that is exposed to the user.
	user []byte
	// Stored is the value that should be stored in the datastore. It can be
	// looked up one-way by the user token.
	stored []byte
	// Encryption is an encryption key bound to this token. It can be generated
	// from the user token, but not from the stored token or any other source.
	// Suitable for AES-256.
	encryption []byte
}

// ToUser returns the value that should be exposed and used by the user.
func (t Token) ToUser(tokenID string) string {
	grantID := t.payload.GetGrantId()
	userID := t.payload.GetUserId()
	builder := TokenData_builder{
		GrantId: &grantID,
		UserId:  &userID,
		TokenId: &tokenID,
		Secret:  t.user,
	}
	td := builder.Build()
	protoBytes, err := proto.Marshal(td)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal token payload: %v", err))
	}
	return o2asPrefix + t.usage.Prefix + "_" + tokenEncoding.EncodeToString(protoBytes)
}

// ID returns the token ID.
func (t Token) ID() string {
	return t.payload.GetTokenId()
}

// Stored returns the value that should be stored in the datastore, for lookups.
func (t Token) Stored() []byte {
	return t.stored
}

// New creates a new token.
func New(usage Usage, grantID, userID string) Token {
	var tok = make([]byte, 32)

	if n, err := rand.Read(tok); err != nil || n != 32 {
		panic(fmt.Sprintf("failed to generate random token: %v", err))
	}

	info := fmt.Sprintf("%s:%s:%s", usage.Name, grantID, userID)

	stored, err := tinksubtle.ComputeHKDF("SHA256", tok, storedSalt, []byte(info), keyLength)
	if err != nil {
		panic(fmt.Sprintf("failed to generate stored token: %v", err))
	}

	encryption, err := tinksubtle.ComputeHKDF("SHA256", tok, encSalt, []byte(info), keyLength)
	if err != nil {
		panic(fmt.Sprintf("failed to generate encryption key: %v", err))
	}

	builder := TokenData_builder{
		GrantId: &grantID,
		UserId:  &userID,
	}
	td := builder.Build()

	return Token{
		user:       tok,
		stored:     stored,
		encryption: encryption,
		usage:      usage,
		payload:    td,
	}
}

// DEKHandle returns a handle to the encrypted DEK decrypted from this token, to
// perform operations with it and re-encrypt it to a new token.
func (t *Token) DEKHandle(encryptedDEK []byte) (*DEKHandle, error) {
	kek, err := newKEK(t.encryption)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEK: %w", err)
	}

	kh, err := keyset.Read(keyset.NewBinaryReader(bytes.NewReader(encryptedDEK)), kek)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset: %w", err)
	}

	return &DEKHandle{
		kh:    kh,
		usage: t.usage,
	}, nil
}

const keyLength = 32

// newKEK creates a new AEAD for the KEK from the provided key.
func newKEK(key []byte) (tink.AEAD, error) {
	if len(key) != keyLength {
		return nil, fmt.Errorf("encryption key is not the correct length")
	}

	return aeadsubtle.NewAESGCM(key)
}
