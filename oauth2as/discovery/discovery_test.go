package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type mockKeysource struct {
	handle *keyset.Handle
}

func (m *mockKeysource) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	if m.handle == nil {
		h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
		if err != nil {
			return nil, fmt.Errorf("creating handle: %v", err)
		}
		h, err = h.Public()
		if err != nil {
			return nil, fmt.Errorf("getting public handle: %w", err)
		}
		m.handle = h
	}

	return m.handle, nil
}

func TestDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := http.NewServeMux()
	ts := httptest.NewServer(m)

	ks := &mockKeysource{}

	kh := NewKeysHandler(ks, 1*time.Nanosecond)
	m.Handle("/jwks.json", kh)

	pm := &ProviderMetadata{
		Issuer:                ts.URL,
		JWKSURI:               ts.URL + "/jwks.json",
		AuthorizationEndpoint: "/auth",
		TokenEndpoint:         "/token",
	}

	ch, err := NewConfigurationHandler(pm, WithCoreDefaults())
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}
	m.Handle(oidcwk, ch)

	cli, err := NewClient(ctx, ts.URL)
	if err != nil {
		t.Fatalf("failed to create discovery client: %v", err)
	}

	_, err = cli.PublicHandle(ctx)
	if err != nil {
		t.Fatalf("getting public handle: %v", err)
	}
}
