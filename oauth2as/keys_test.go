package oauth2as

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
)

func TestLocalJWTSigner(t *testing.T) {
	ctx := t.Context()
	esKey := mustECDSAKey(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := mustECDSAKey(t)

	signer, err := NewLocalJWTSigner(LocalJWTSignerConfig{
		SigningKeys: []SigningKey{
			{Algorithm: jwt.RS256, Key: rsaKey},
			{Algorithm: jwt.ES256, Key: esKey},
		},
		VerificationKeys: []crypto.PublicKey{oldKey.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}

	algorithms, err := signer.Algorithms(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(algorithms, []jwt.Algorithm{jwt.ES256, jwt.RS256}) {
		t.Fatalf("unexpected algorithms: %v", algorithms)
	}

	jwks, err := signer.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := signer.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(jwks) != string(second) {
		t.Fatal("JWKS output is not deterministic")
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := jsonv2.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 3 {
		t.Fatalf("want 3 public keys, got %d", len(set.Keys))
	}
	active := 0
	for _, key := range set.Keys {
		if key["kid"] == "" || key["use"] != "sig" {
			t.Fatalf("invalid published JWK: %v", key)
		}
		if key["d"] != nil {
			t.Fatalf("private key material was published: %v", key)
		}
		if key["alg"] != nil {
			active++
		}
	}
	if active != 2 {
		t.Fatalf("want 2 active keys with alg metadata, got %d", active)
	}

	now := time.Now()
	payload, err := jsonv2.Marshal(map[string]any{
		"iss": "https://issuer.example",
		"sub": "subject",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.SignJWT(ctx, jwt.ES256, JWTSigningInput{Type: "at+jwt", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	header := decodeJWTHeader(t, compact)
	if header["alg"] != "ES256" || header["typ"] != "at+jwt" || header["kid"] == "" {
		t.Fatalf("unexpected protected header: %v", header)
	}
	verified, err := signer.VerifyJWT(ctx, compact, jwt.ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		IgnoreAudiences:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		ExpectedType:      "at+jwt",
		ClockSkew:         jwt.DefaultClockSkew,
		RequireIssuedAt:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := verified.Subject(); err != nil || subject != "subject" {
		t.Fatalf("unexpected verified subject %q: %v", subject, err)
	}

	oldSigner, err := NewLocalJWTSignerForKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := oldSigner.SignJWT(ctx, jwt.ES256, JWTSigningInput{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.VerifyJWT(ctx, oldToken, jwt.ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		IgnoreAudiences:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		ClockSkew:         jwt.DefaultClockSkew,
		RequireIssuedAt:   true,
	}); err != nil {
		t.Fatalf("verification-only rotation key was not accepted: %v", err)
	}
}

func TestLocalJWTSignerRejectsInvalidConfiguration(t *testing.T) {
	key := mustECDSAKey(t)
	tests := []struct {
		name   string
		config LocalJWTSignerConfig
		want   string
	}{
		{name: "no signing key", want: "at least one signing key"},
		{
			name: "algorithm incompatible with key",
			config: LocalJWTSignerConfig{SigningKeys: []SigningKey{
				{Algorithm: jwt.RS256, Key: key},
			}},
			want: "incompatible",
		},
		{
			name: "same key also used for verification",
			config: LocalJWTSignerConfig{
				SigningKeys:      []SigningKey{{Algorithm: jwt.ES256, Key: key}},
				VerificationKeys: []crypto.PublicKey{key.Public()},
			},
			want: "duplicate key thumbprint",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewLocalJWTSigner(test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("want error containing %q, got %v", test.want, err)
			}
		})
	}
}

func mustECDSAKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decodeJWTHeader(t testing.TB, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := jsonv2.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	return header
}
