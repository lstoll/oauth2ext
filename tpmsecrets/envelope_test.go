package tpmsecrets

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/tokencache"
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
	wantKey := []byte("wrapped-key")

	if err := cache.Set("https://issuer.example", "client", &tokencache.Credential{Token: want, DPoPKey: wantKey}); err != nil {
		t.Fatal(err)
	}
	cred, err := cache.Get("https://issuer.example", "client")
	if err != nil {
		t.Fatal(err)
	}
	if cred == nil || !bytes.Equal(cred.DPoPKey, wantKey) {
		t.Fatalf("unexpected credential: %#v", cred)
	}
	got := cred.Token
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
	if err := cache.Set("https://issuer.example", "client", &tokencache.Credential{Token: want}); err == nil {
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

func TestTPMCredentialCacheConcurrentSet(t *testing.T) {
	cache := &TPMCredentialCache{Dir: t.TempDir(), sealer: memoryKeySealer{marker: []byte("m")}}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			// Separate instances, as separate processes would have. flock is
			// per open file description, so this excludes across them.
			c := &TPMCredentialCache{Dir: cache.Dir, sealer: cache.sealer}
			errs <- c.Set("https://issuer.example", fmt.Sprintf("client-%d", i), &tokencache.Credential{Token: &oauth2.Token{AccessToken: fmt.Sprintf("tok-%d", i)}})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range n {
		cred, err := cache.Get("https://issuer.example", fmt.Sprintf("client-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if cred == nil || cred.Token.AccessToken != fmt.Sprintf("tok-%d", i) {
			t.Fatalf("entry %d lost: %#v", i, cred)
		}
	}
}

func TestTPMCredentialCacheFailedWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	// A directory at the target path makes the final rename fail.
	if err := os.Mkdir(filepath.Join(dir, cacheDataFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(dir, cacheDataFile), []byte("data")); err == nil {
		t.Fatal("expected write failure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestDecodeDPoPHandle(t *testing.T) {
	good, err := encodeDPoPHandle([]byte("pub"), []byte("priv"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := decodeDPoPHandle(good)
	if err != nil || string(pub) != "pub" || string(priv) != "priv" {
		t.Fatalf("round trip failed: %q %q %v", pub, priv, err)
	}

	huge := binary.BigEndian.AppendUint32([]byte{dpopHandleVersion}, maxTPMSealedPartSize+1)
	zero := binary.BigEndian.AppendUint32([]byte{dpopHandleVersion}, 0)
	for name, h := range map[string][]byte{
		"nil":             nil,
		"bad version":     append([]byte{9}, good[1:]...),
		"version only":    {dpopHandleVersion},
		"truncated len":   good[:3],
		"truncated pub":   good[:6],
		"truncated priv":  good[:len(good)-1],
		"trailing":        append(bytes.Clone(good), 0),
		"oversized":       huge,
		"zero length":     zero,
		"missing private": good[:1+4+3],
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeDPoPHandle(h); err == nil {
				t.Fatal("malformed handle accepted")
			}
		})
	}

	// Well-framed but garbage TPM structures must fail in LoadDPoPKey.
	c := new(TPMCredentialCache)
	if _, err := c.LoadDPoPKey(good); err == nil {
		t.Fatal("garbage TPM public accepted")
	}
}
