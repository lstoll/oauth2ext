package jwt

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

type AccessTokenVerifier struct {
	Provider       Provider
	OverrideKeyset PublicKeyset

	WantAnyAudience []string
	IgnoreAudience  bool
}

func (a *AccessTokenVerifier) Verify(ctx context.Context, token *oauth2.Token) (*AccessTokenClaims, error) {
	return a.VerifyRaw(ctx, token.AccessToken)
}

func (a *AccessTokenVerifier) VerifyRaw(ctx context.Context, rawJWT string) (*AccessTokenClaims, error) {
	vopts := verifyOpts{
		Issuer:          a.Provider.GetIssuer(),
		WantType:        JWTTYPAccessToken,
		SupportedAlgs:   algsToJOSEAlgs(a.Provider.GetSupportedAlgs()),
		WantAnyAudience: jwt.Audience(a.WantAnyAudience),
		SkipAudience:    a.IgnoreAudience,
		ValidTimeBuffer: defaultValidTimeBuffer,
	}

	jwt, err := verifyToken(ctx, a.keyset(), rawJWT, vopts)
	if err != nil {
		return nil, fmt.Errorf("verifying access_token: %w", err)
	}

	var cl AccessTokenClaims
	if err := jwt.UnmarshalClaims(&cl); err != nil {
		return nil, fmt.Errorf("unmarshalling access_token: %w", err)
	}

	return &cl, nil
}

func (a *AccessTokenVerifier) keyset() PublicKeyset {
	if a.OverrideKeyset != nil {
		return a.OverrideKeyset
	}
	return a.Provider.GetKeyset()
}
