package clitoken

import (
	"testing"

	"lds.li/oauth2ext/internal/platformsecrets"
	"lds.li/oauth2ext/jwt"
)

func TestMemoryWriteThroughCredentialCache(t *testing.T) {
	cache := &MemCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	platformsecrets.TestStore(t, cache)
}

func TestMemCredentialCacheAlgorithmSelection(t *testing.T) {
	cache := &MemCredentialCache{}

	for _, tc := range []struct {
		name    string
		offered []jwt.Algorithm
		want    jwt.Algorithm
	}{
		{"first in order", []jwt.Algorithm{jwt.MLDSA65, jwt.ES256}, jwt.MLDSA65},
		{"order respected", []jwt.Algorithm{jwt.ES256, jwt.MLDSA65}, jwt.ES256},
		{"skips unsupported", []jwt.Algorithm{"HS256", jwt.ES384}, jwt.ES384},
		{"EdDSA", []jwt.Algorithm{jwt.EdDSA}, jwt.EdDSA},
		{"RSA for PS256", []jwt.Algorithm{jwt.PS256}, jwt.PS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handle, key, err := cache.NewDPoPKey(tc.offered)
			if err != nil {
				t.Fatal(err)
			}
			id, err := jwt.NewSigningIdentity(key, tc.want, "")
			if err != nil {
				t.Fatal(err)
			}
			if id.Algorithm() != tc.want {
				t.Fatalf("got algorithm %s, want %s", id.Algorithm(), tc.want)
			}

			loaded, err := cache.LoadDPoPKey(handle)
			if err != nil {
				t.Fatal(err)
			}
			loadedID, err := jwt.NewSigningIdentity(loaded, tc.want, "")
			if err != nil {
				t.Fatal(err)
			}
			if id.Thumbprint() != loadedID.Thumbprint() || loadedID.Algorithm() != tc.want {
				t.Fatalf("loaded key differs: %s/%s", loadedID.Algorithm(), loadedID.Thumbprint())
			}
		})
	}

	if _, _, err := cache.NewDPoPKey([]jwt.Algorithm{"HS256"}); err == nil {
		t.Fatal("expected error when no algorithm is supported")
	}
}
