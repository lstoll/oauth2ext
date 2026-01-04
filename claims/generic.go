package claims

import (
	"context"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal/th"
)

type Validator[Claims Claimable] interface {
	// ValidatorOpts returns the basic tink validator options that will be used
	// to validate the JWT initially. The issuer will always be overridden by
	// the provider's issuer.
	ValidatorOpts() *jwt.ValidatorOpts
	// Validate is passed the verified JWT and can perform additional checks,
	// before returning the claims type.
	Validate(jwt *jwt.VerifiedJWT) (Claims, error)
	// CompactFromToken is used to extract the compact JWT from the OAuth2 token.
	CompactFromToken(token oauth2.Token) (string, error)
}

type Claimable any

// Provider represents the OIDC Provider or OAuth2 Authorization Server.
type Provider interface {
	// Issuer returns the issuer URL for the provider.
	Issuer() string
	jwt.Verifier
}

// JWTVerifierWithContext is an optional interface the provider can implement.
// If implemented, it will be used to verify the JWT token.
type JWTVerifierWithContext interface {
	VerifyAndDecodeContext(ctx context.Context, compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error)
}

type Verifier[Claims Claimable] struct {
	provider Provider
}

func NewVerifier[Claims Claimable](provider Provider) (*Verifier[Claims], error) {
	return &Verifier[Claims]{
		provider: provider,
	}, nil
}

func (v *Verifier[Claims]) VerifyAndDecode(ctx context.Context, compact string, validator Validator[Claims]) (Claims, error) {
	var empty Claims

	vo := validator.ValidatorOpts()
	vo.ExpectedIssuer = th.Ptr(v.provider.Issuer())
	tinkValidator, err := jwt.NewValidator(vo)
	if err != nil {
		return empty, err
	}

	var jwt *jwt.VerifiedJWT
	ctxVerifier, ok := v.provider.(JWTVerifierWithContext)
	if ok {
		jwt, err = ctxVerifier.VerifyAndDecodeContext(ctx, compact, tinkValidator)
		if err != nil {
			return empty, err
		}
	} else {
		jwt, err = v.provider.VerifyAndDecode(compact, tinkValidator)
		if err != nil {
			return empty, err
		}
	}

	return validator.Validate(jwt)
}

func (v *Verifier[Claims]) VerifyAndDecodeToken(ctx context.Context, token oauth2.Token, validator Validator[Claims]) (Claims, error) {
	var empty Claims

	compact, err := validator.CompactFromToken(token)
	if err != nil {
		return empty, err
	}
	return v.VerifyAndDecode(ctx, compact, validator)
}
