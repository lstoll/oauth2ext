package jwt

import (
	"fmt"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func validateClaims(m map[string]any, policy ValidationPolicy, now time.Time) error {
	claims, got, err := joseClaimsFromMap(m)
	if err != nil {
		return verificationErrorf(VerificationErrorCodeClaim, "decoding registered claims: %v", err)
	}

	if !policy.AllowMissingExpiration && !got.exp {
		return verificationErrorf(VerificationErrorCodeClaim, "missing exp claim")
	}
	if policy.RequireIssuedAt && !got.iat {
		return verificationErrorf(VerificationErrorCodeClaim, "missing iat claim")
	}
	if !policy.IgnoreAudiences && !got.aud {
		return verificationErrorf(VerificationErrorCodeAudience, "missing aud claim; want one of %v", policy.ExpectedAudiences)
	}

	expected := josejwt.Expected{Time: now}
	if !policy.IgnoreIssuer {
		expected.Issuer = policy.ExpectedIssuer
	}
	if !policy.IgnoreAudiences {
		expected.AnyAudience = josejwt.Audience(policy.ExpectedAudiences)
	}

	if err := claims.ValidateWithLeeway(expected, policy.ClockSkew); err != nil {
		return mapValidateError(err, claims, policy)
	}
	return nil
}

type claimPresence struct {
	aud, exp, nbf, iat bool
}

func joseClaimsFromMap(m map[string]any) (josejwt.Claims, claimPresence, error) {
	var (
		claims josejwt.Claims
		got    claimPresence
	)

	issuer, present, err := registeredClaim[string](m, "iss")
	if err != nil {
		return claims, got, err
	}
	if present {
		claims.Issuer = issuer
	}
	subject, present, err := registeredClaim[string](m, "sub")
	if err != nil {
		return claims, got, err
	}
	if present {
		claims.Subject = subject
	}
	id, present, err := registeredClaim[string](m, "jti")
	if err != nil {
		return claims, got, err
	}
	if present {
		claims.ID = id
	}

	if value, ok := m["aud"]; ok {
		audiences, err := stringsOrString(value, "aud")
		if err != nil {
			return claims, got, err
		}
		claims.Audience = josejwt.Audience(audiences)
		got.aud = true
	}

	if value, ok := m["exp"]; ok {
		t, err := numericDate(value, "exp")
		if err != nil {
			return claims, got, err
		}
		claims.Expiry = josejwt.NewNumericDate(t)
		got.exp = true
	}
	if value, ok := m["nbf"]; ok {
		t, err := numericDate(value, "nbf")
		if err != nil {
			return claims, got, err
		}
		claims.NotBefore = josejwt.NewNumericDate(t)
		got.nbf = true
	}
	if value, ok := m["iat"]; ok {
		t, err := numericDate(value, "iat")
		if err != nil {
			return claims, got, err
		}
		claims.IssuedAt = josejwt.NewNumericDate(t)
		got.iat = true
	}
	return claims, got, nil
}

func registeredClaim[T any](claims map[string]any, name string) (T, bool, error) {
	var zero T
	value, ok := claims[name]
	if !ok {
		return zero, false, nil
	}
	out, ok := value.(T)
	if !ok {
		return zero, true, typeError(name, fmt.Sprintf("%T", zero))
	}
	return out, true, nil
}
