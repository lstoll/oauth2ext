package claims

import (
	"context"
	"errors"

	"golang.org/x/oauth2"
)

var errNilIDClaimsMapper = errors.New("claims: nil ID claims mapper")

// IDClaimsMapper projects a verified standard ID token into application claims.
type IDClaimsMapper[Claims any] func(*VerifiedID) (Claims, error)

// IDClaimsRule applies application policy to projected ID claims.
type IDClaimsRule[Claims any] func(Claims) error

// WithIDClaimsRules returns a mapper that applies every rule in order after
// projection. All rules must succeed.
func WithIDClaimsRules[Claims any](mapper IDClaimsMapper[Claims], rules ...IDClaimsRule[Claims]) IDClaimsMapper[Claims] {
	return func(id *VerifiedID) (Claims, error) {
		var zero Claims
		if mapper == nil {
			return zero, errNilIDClaimsMapper
		}
		mapped, err := mapper(id)
		if err != nil {
			return zero, err
		}
		for _, rule := range rules {
			if rule == nil {
				return zero, errors.New("claims: nil ID claims rule")
			}
			if err := rule(mapped); err != nil {
				return zero, err
			}
		}
		return mapped, nil
	}
}

// AnyIDClaimsRule succeeds when any supplied rule succeeds.
func AnyIDClaimsRule[Claims any](rules ...IDClaimsRule[Claims]) IDClaimsRule[Claims] {
	return func(claims Claims) error {
		if len(rules) == 0 {
			return errors.New("claims: at least one ID claims rule is required")
		}
		var failures []error
		for _, rule := range rules {
			if rule == nil {
				failures = append(failures, errors.New("claims: nil ID claims rule"))
				continue
			}
			err := rule(claims)
			if err == nil {
				return nil
			}
			failures = append(failures, err)
		}
		return errors.Join(failures...)
	}
}

// IDTokenResponseVerifier verifies ID tokens supplied directly or in an OAuth2
// token response and returns standard or application-specific claims.
type IDTokenResponseVerifier[Claims any] interface {
	Verify(ctx context.Context, compact string, input IDTokenValidationInput) (Claims, error)
	VerifyTokenResponse(ctx context.Context, token *oauth2.Token, input IDTokenValidationInput) (Claims, error)
}

// MappedIDTokenVerifier projects verified standard ID claims into an
// application-specific type.
type MappedIDTokenVerifier[Claims any] struct {
	verifier *IDTokenVerifier
	mapper   IDClaimsMapper[Claims]
}

// MapIDTokenClaims applies mapper after standard ID-token validation.
func MapIDTokenClaims[Claims any](verifier *IDTokenVerifier, mapper IDClaimsMapper[Claims]) *MappedIDTokenVerifier[Claims] {
	return &MappedIDTokenVerifier[Claims]{verifier: verifier, mapper: mapper}
}

func (v *MappedIDTokenVerifier[Claims]) Verify(ctx context.Context, compact string, input IDTokenValidationInput) (Claims, error) {
	var zero Claims
	if v == nil || v.verifier == nil {
		return zero, errors.New("claims: invalid mapped ID token verifier")
	}
	id, err := v.verifier.Verify(ctx, compact, input)
	if err != nil {
		return zero, err
	}
	if v.mapper == nil {
		return zero, errNilIDClaimsMapper
	}
	return v.mapper(id)
}

func (v *MappedIDTokenVerifier[Claims]) VerifyTokenResponse(ctx context.Context, token *oauth2.Token, input IDTokenValidationInput) (Claims, error) {
	var zero Claims
	if v == nil || v.verifier == nil {
		return zero, errors.New("claims: invalid mapped ID token verifier")
	}
	id, err := v.verifier.VerifyTokenResponse(ctx, token, input)
	if err != nil {
		return zero, err
	}
	if v.mapper == nil {
		return zero, errNilIDClaimsMapper
	}
	return v.mapper(id)
}
