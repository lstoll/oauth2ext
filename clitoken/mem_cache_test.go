package clitoken

import (
	"testing"

	"lds.li/oauth2ext/internal/platformsecrets"
)

func TestMemoryWriteThroughCredentialCache(t *testing.T) {
	cache := &MemCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	platformsecrets.TestCache(t, cache)
}
