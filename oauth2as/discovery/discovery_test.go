package discovery_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oauth2as/discovery"
	"lds.li/oauth2ext/oauth2as/internal"
	"lds.li/oauth2ext/provider"
)

func TestDiscovery(t *testing.T) {
	ctx := t.Context()
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	t.Cleanup(cancel)

	testSigner := internal.NewTestSigner(t)

	m := http.NewServeMux()
	ts := httptest.NewTLSServer(m)
	defer ts.Close()

	pm := discovery.DefaultCoreMetadata(ts.URL)
	pm.AuthorizationEndpoint = ts.URL + "/authorization"
	pm.TokenEndpoint = ts.URL + "/token"
	pm.IDTokenSigningAlgValuesSupported = []string{"ES256"}

	ch, err := discovery.NewOIDCConfigurationHandlerWithKeyset(pm, testSigner)
	if err != nil {
		t.Fatalf("error creating handler: %v", err)
	}

	m.Handle("GET /.well-known/", ch)

	discCtx := context.WithValue(ctx, oauth2.HTTPClient, ts.Client())
	p, err := provider.DiscoverOIDCProvider(discCtx, ts.URL)
	if err != nil {
		t.Fatalf("failed to discover provider: %v", err)
	}
	_ = p

	// TODO - instpect what was discovered?
}
