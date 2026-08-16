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
// generated when omitted. Certificate chains are omitted by default; set
// IncludeCertificates only when the verifier requires a trusted x5c chain.
// Certificate chains can disclose organization or host identity to every
// DPoP recipient.
type ProofOptions struct {
	HTTPMethod string
	HTTPURI    string
	IssuedAt   time.Time
	Nonce      string
	// AccessToken, when set, is hashed into the ath claim.
	AccessToken string
	// IncludeCertificates opts into emitting the signer's configured x5c chain.
	IncludeCertificates bool
}

// dpopAlgorithms are the asymmetric algorithms this package accepts for DPoP
// proofs. Sign and verification derive their respective JOSE settings from
// this one policy.
var dpopAlgorithms = []jwt.Algorithm{
	jwt.RS256, jwt.RS384, jwt.RS512,
	jwt.PS256, jwt.PS384, jwt.PS512,
	jwt.ES256, jwt.ES384, jwt.ES512,
	jwt.EdDSA,
}

// Sign creates a compact DPoP proof using signer. The proof uses typ
// "dpop+jwt", embeds the public JWK, and omits kid. Its identity argument is
// immutable, so a proof cannot silently change keys between requests.
func Sign(ctx context.Context, signer *jwt.SigningIdentity, options ProofOptions) (string, error) {
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
	certificateMode := jwt.OmitCertificates
	if options.IncludeCertificates {
		certificateMode = jwt.RequireCertificates
	}
	return signer.Sign(ctx, payload, jwt.SignOptions{
		Type:         "dpop+jwt",
		SkipKeyID:    true,
		IncludeJWK:   true,
		Certificates: certificateMode,
	})
}

func hashAccessToken(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
