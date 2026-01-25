package platformsecrets

import (
	"testing"
)

func TestMemoryWriteThroughCredentialCache(t *testing.T) {
	cache := &MemCredentialCache{}

	if !cache.Available() {
		t.Fatal("cache is not available")
	}

	TestCache(t, cache)
}
