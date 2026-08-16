package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
	"uuid"

	"lds.li/oauth2ext/jwt"
)

// ProofOptions contains the claims used to create a DPoP proof. IssuedAt is
// generated when omitted.
type ProofOptions struct {
	HTTPMethod string
	HTTPURI    string
	IssuedAt   time.Time
	Nonce      string
	// AccessToken, when set, is hashed into the ath claim.
	AccessToken string
}

// Sign creates a compact DPoP proof using signer. The proof uses typ
// "dpop+jwt", embeds the public JWK, and omits kid. Certificate chains are
// requested; signers that do not support x5c are retried without it.
func Sign(ctx context.Context, signer *jwt.Signer, options ProofOptions) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("dpop: signer is required")
	}
	if options.HTTPMethod == "" {
		return "", fmt.Errorf("dpop: HTTPMethod is required")
	}
	if options.HTTPURI == "" {
		return "", fmt.Errorf("dpop: HTTPURI is required")
	}
	if options.IssuedAt.IsZero() {
		options.IssuedAt = time.Now()
	}
	payload := map[string]any{
		"jti": uuid.NewV4().String(),
		"htm": options.HTTPMethod,
		"htu": options.HTTPURI,
		"iat": float64(options.IssuedAt.Unix()) + float64(options.IssuedAt.Nanosecond())/float64(time.Second),
	}
	if options.Nonce != "" {
		payload["nonce"] = options.Nonce
	}
	if options.AccessToken != "" {
		payload["ath"] = hashAccessToken(options.AccessToken)
	}
	return signer.Sign(ctx, payload, jwt.SignOptions{
		Type:         "dpop+jwt",
		SkipKeyID:    true,
		IncludeJWK:   true,
		Certificates: jwt.IncludeCertificatesIfAvailable,
	})
}

func hashAccessToken(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
