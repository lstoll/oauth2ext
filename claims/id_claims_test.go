package claims

import (
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/internal/th"
)

func TestIDClaims(t *testing.T) {
	rawOpts := &RawIDOptions{
		Issuer:    th.Ptr("https://example.com"),
		ClientID:  th.Ptr("https://example.com"),
		Subject:   th.Ptr("https://example.com"),
		IssuedAt:  th.Ptr(time.Now()),
		ExpiresAt: th.Ptr(time.Now().Add(1 * time.Hour)),
		NotBefore: th.Ptr(time.Now()),
		AMR:       []string{"amr1", "amr2"},
	}

	_, err := jwt.NewRawJWT(rawOpts.JWTOptions())
	if err != nil {
		t.Fatal(err)
	}
}
