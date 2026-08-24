package tpmsecrets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/oauth2"
)

type memoryKeySealer struct {
	marker []byte
	err    error
}

func (s memoryKeySealer) Seal(key []byte) (sealedBlob, error) {
	if s.err != nil {
		return sealedBlob{}, s.err
	}
	return sealedBlob{
		Public:  append([]byte(nil), s.marker...),
		Private: append([]byte(nil), key...),
	}, nil
}

func (s memoryKeySealer) Unseal(blob sealedBlob) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if !bytes.Equal(blob.Public, s.marker) {
		return nil, errors.New("wrong public blob")
	}
	return append([]byte(nil), blob.Private...), nil
}

func TestCredentialCacheEnvelope(t *testing.T) {
	sealer := memoryKeySealer{marker: []byte("test-sealed-key")}
	plaintext := []byte(`{"token":"secret"}`)

	first, err := encryptCredentialCache(sealer, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := encryptCredentialCache(sealer, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("fresh envelope encryption produced identical output")
	}
	if !bytes.HasPrefix(first, cacheEnvelopeMagic) {
		t.Fatalf("missing cache envelope magic: %x", first)
	}
	decrypted, err := decryptCredentialCache(sealer, first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("want %q, got %q", plaintext, decrypted)
	}

	publicSize := int(binary.BigEndian.Uint32(first[6:10]))
	privateSize := int(binary.BigEndian.Uint32(first[10:14]))
	positions := map[string]int{
		"magic":       0,
		"version":     4,
		"algorithm":   5,
		"public key":  cacheEnvelopeFixedSize,
		"private key": cacheEnvelopeFixedSize + publicSize,
		"nonce":       cacheEnvelopeFixedSize + publicSize + privateSize,
		"ciphertext":  len(first) - 1,
	}
	for name, position := range positions {
		t.Run("tampered "+name, func(t *testing.T) {
			tampered := bytes.Clone(first)
			tampered[position] ^= 1
			if _, err := decryptCredentialCache(sealer, tampered); err == nil {
				t.Fatal("tampered envelope was accepted")
			}
		})
	}
}

func TestCredentialCacheEnvelopeRejectsMalformedInput(t *testing.T) {
	sealer := memoryKeySealer{marker: []byte("test-sealed-key")}
	badLengths := make([]byte, cacheEnvelopeFixedSize)
	copy(badLengths, cacheEnvelopeMagic)
	badLengths[4] = cacheEnvelopeVersion
	badLengths[5] = cacheEnvelopeAES256GCM
	binary.BigEndian.PutUint32(badLengths[6:10], maxTPMSealedPartSize+1)
	binary.BigEndian.PutUint32(badLengths[10:14], 1)

	for name, envelope := range map[string][]byte{
		"empty":           nil,
		"legacy Tink":     []byte(`{"encryptedKeyset":"legacy"}`),
		"truncated":       append([]byte(nil), cacheEnvelopeMagic...),
		"invalid lengths": badLengths,
		"oversized":       make([]byte, maxCacheEnvelopeSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decryptCredentialCache(sealer, envelope); err == nil {
				t.Fatal("malformed envelope was accepted")
			}
		})
	}

	broken := memoryKeySealer{marker: []byte("test"), err: errors.New("sealer unavailable")}
	if _, err := encryptCredentialCache(broken, []byte("data")); err == nil {
		t.Fatal("key-sealing failure was ignored")
	}
}

func TestTPMCredentialCacheWithMemorySealer(t *testing.T) {
	sealer := memoryKeySealer{marker: []byte("test-sealed-key")}
	cache := &TPMCredentialCache{Dir: t.TempDir(), sealer: sealer}
	want := &oauth2.Token{AccessToken: "access-token", RefreshToken: "refresh-token", TokenType: "Bearer"}

	if err := cache.Set("https://issuer.example", "client", want); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get("https://issuer.example", "client")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken || got.TokenType != want.TokenType {
		t.Fatalf("unexpected cached token: %#v", got)
	}
	missing, err := cache.Get("https://issuer.example", "other-client")
	if err != nil || missing != nil {
		t.Fatalf("want cache miss, got %#v, %v", missing, err)
	}

	cachePath := filepath.Join(cache.Dir, cacheDataFile)
	if err := os.WriteFile(cachePath, []byte("legacy-or-corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.Set("https://issuer.example", "client", want); err == nil {
		t.Fatal("Set silently replaced an unreadable existing cache")
	}
	contents, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "legacy-or-corrupt" {
		t.Fatal("unreadable cache was overwritten")
	}
}

func TestTPMCredentialCacheKeyIsUnambiguous(t *testing.T) {
	cache := new(TPMCredentialCache)
	if cache.cacheKey("a;b", "c") == cache.cacheKey("a", "b;c") {
		t.Fatal("distinct issuer/key pairs produced the same cache key")
	}
}
