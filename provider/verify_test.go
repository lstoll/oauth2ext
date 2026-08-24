package provider

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

func TestProviderVerifyJWT(t *testing.T) {
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

	verified, err := p.VerifyJWT(ctx, compact, jwt.ValidationPolicy{
		ExpectedAudiences: []string{"client"},
		RequireIssuedAt:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
	})
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
	got := algorithmsFromMetadata([]string{"HS256", "ES256", "unknown"})
	if len(got) != 1 || got[0] != jwt.ES256 {
		t.Fatalf("algorithms: got %v, want [ES256]", got)
	}
}
