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

func PublicHandle() *keyset.Handle {
	h, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		panic(fmt.Sprintf("creating handle: %v", err))
	}
	h, err = h.Public()
	if err != nil {
		panic(fmt.Sprintf("getting public handle: %v", err))
	}

	return h
}

func TestDiscovery(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := http.NewServeMux()
	ts := httptest.NewServer(m)

	kh, err := NewKeysHandler(PublicHandle, 1*time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
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

	_, err = NewClient(ctx, ts.URL)
	if err != nil {
		t.Fatalf("failed to create discovery client: %v", err)
	}
}
