package discovery_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lstoll/oauth2ext/internal"
	"github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oauth2as/discovery"
	"github.com/lstoll/oauth2ext/oidc"
	"golang.org/x/oauth2"
)

func TestDiscovery(t *testing.T) {
	ctx := t.Context()
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	t.Cleanup(cancel)

	testSigner := internal.NewTestSigner(t)

	mockKeyset, err := jwt.NewStaticKeysetFromJWKS(testSigner.JWKS())
	if err != nil {
		t.Fatalf("failed to create mock keyset: %v", err)
	}

	m := http.NewServeMux()
	ts := httptest.NewTLSServer(m)
	defer ts.Close()

	pm := discovery.DefaultCoreMetadata(ts.URL)
	pm.AuthorizationEndpoint = ts.URL + "/authorization"
	pm.TokenEndpoint = ts.URL + "/token"
	pm.IDTokenSigningAlgValuesSupported = []string{string(jwt.SigningAlgES256)}

	ch, err := discovery.NewOIDCConfigurationHandlerWithKeyset(pm, mockKeyset)
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}

	m.Handle("GET /.well-known/", ch)

	discCtx := context.WithValue(ctx, oauth2.HTTPClient, ts.Client())
	p, err := oidc.DiscoverProvider(discCtx, ts.URL)
	if err != nil {
		t.Fatalf("failed to discover provider: %v", err)
	}

	if p.GetIssuerURL() != ts.URL {
		t.Errorf("expected issuer %s, got %s", ts.URL, p.GetIssuerURL())
	}

	keyset := p.GetKeyset()
	if keyset == nil {
		t.Fatal("provider keyset is nil")
	}

	allKeys, err := mockKeyset.GetKeys(ctx)
	if err != nil {
		t.Fatalf("failed to get all keys from mock keyset: %v", err)
	}

	if len(allKeys) == 0 {
		t.Fatal("no keys found in mock keyset")
	}

	// Use the first key's KID for testing
	testKID := allKeys[0].KeyID

	keys, err := keyset.GetKeysByKID(ctx, testKID)
	if err != nil {
		t.Fatalf("failed to get keys by KID: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("no keys found for test KID")
	}

	found := false
	for _, key := range keys {
		if key.KeyID == testKID {
			found = true
			if key.Alg != jwt.SigningAlgES256 {
				t.Errorf("expected algorithm ES256, got %s", key.Alg)
			}
			break
		}
	}

	if !found {
		t.Fatal("test key not found in discovered keyset")
	}
}
