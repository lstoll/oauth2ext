package oauth2as

import (
	"testing"
)

func TestMemStorage(t *testing.T) {
	TestStorage(t, func(*testing.T) Storage {
		return NewMemStorage()
	})
}
