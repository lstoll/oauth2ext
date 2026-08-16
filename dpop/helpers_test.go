package dpop

import (
	"crypto"
	"crypto/x509"
	"testing"

	"lds.li/oauth2ext/jwt"
)

func mustSigner(t *testing.T, key crypto.Signer) *jwt.Signer {
	t.Helper()
	return mustSignerConfig(t, key, "", nil)
}

func mustSignerWithCerts(t *testing.T, key crypto.Signer, chain []*x509.Certificate) *jwt.Signer {
	t.Helper()
	return mustSignerConfig(t, key, "", chain)
}

func mustSignerConfig(t *testing.T, key crypto.Signer, algorithm jwt.Algorithm, certificates []*x509.Certificate) *jwt.Signer {
	t.Helper()
	signer, err := jwt.NewSigner(key, algorithm, "", certificates...)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func dpopSignOpts() jwt.SignOptions {
	return jwt.SignOptions{
		Type:       "dpop+jwt",
		SkipKeyID:  true,
		IncludeJWK: true,
	}
}

func mustSignClaims(t *testing.T, signer *jwt.Signer, claims map[string]any, opts jwt.SignOptions) string {
	t.Helper()
	compact, err := signer.Sign(t.Context(), claims, opts)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
