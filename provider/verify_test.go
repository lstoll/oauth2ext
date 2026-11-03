package provider

import (
	"context"
	"slices"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

func TestProviderVerifier(t *testing.T) {
	svr, signer := newMockDiscoveryServer(t)
	t.Cleanup(svr.Close)

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, svr.Client())
	p, err := DiscoverOIDCProvider(ctx, svr.URL)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	compact, err := signer.SignClaims(map[string]any{
		"iss": svr.URL,
		"sub": "subject",
		"aud": "client",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := p.Verifier(ctx, jwt.ValidationPolicy{
		ExpectedAudiences: []string{"client"},
		Type:              jwt.TypeAny,
		RequireIssuedAt:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(compact)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := verified.Subject()
	if err != nil {
		t.Fatal(err)
	}
	if sub != "subject" {
		t.Fatalf("subject: %q", sub)
	}
}

func TestAlgorithmsFromMetadataIgnoresUnsupportedAlgorithms(t *testing.T) {
	got := algorithmsFromMetadata([]string{"HS256", "ES256", "ML-DSA-44", "ml-dsa-65", "ML-DSA-87", "unknown"})
	want := []jwt.Algorithm{jwt.ES256, jwt.MLDSA44, jwt.MLDSA87}
	if !slices.Equal(got, want) {
		t.Fatalf("algorithms: got %v, want %v", got, want)
	}
}
