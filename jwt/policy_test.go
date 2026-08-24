package jwt

import (
	"errors"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestValidationPolicyRequiresExplicitDecisions(t *testing.T) {
	valid := ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []Algorithm{ES256},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid policy: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ValidationPolicy)
	}{
		{"missing issuer decision", func(p *ValidationPolicy) { p.IgnoreIssuer = false }},
		{"conflicting issuer decision", func(p *ValidationPolicy) { p.ExpectedIssuer = "issuer" }},
		{"missing audience decision", func(p *ValidationPolicy) { p.IgnoreAudiences = false }},
		{"conflicting audience decision", func(p *ValidationPolicy) { p.ExpectedAudiences = []string{"audience"} }},
		{"empty expected audience", func(p *ValidationPolicy) {
			p.IgnoreAudiences = false
			p.ExpectedAudiences = []string{""}
		}},
		{"missing algorithms", func(p *ValidationPolicy) { p.AllowedAlgorithms = nil }},
		{"negative clock skew", func(p *ValidationPolicy) { p.ClockSkew = -time.Second }},
		{"excessive clock skew", func(p *ValidationPolicy) { p.ClockSkew = MaxClockSkew + time.Nanosecond }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := valid
			tt.mutate(&policy)
			if err := policy.validate(); !errors.Is(err, ErrPolicy) {
				t.Fatalf("error: got %v, want ErrPolicy", err)
			}
		})
	}
}

func TestValidationPolicyAllowsMaximumClockSkew(t *testing.T) {
	policy := ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []Algorithm{ES256},
		ClockSkew:         MaxClockSkew,
	}
	if err := policy.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestClockSkewAppliesLeeway(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{"exp": float64(now.Add(-30 * time.Second).Unix())}
	policy := ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []Algorithm{ES256},
	}
	requireVerificationError(t, validateClaims(claims, policy, now), VerificationErrorCodeExpired)
	policy.ClockSkew = DefaultClockSkew
	if err := validateClaims(claims, policy, now); err != nil {
		t.Fatalf("validation with default clock skew: %v", err)
	}
}

func TestVerifyRequiresExpirationByDefault(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{"sub": "subject"})
	_, err := signer.keySet.VerifyJWT(compact, ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []Algorithm{ES256},
	})
	requireVerificationError(t, err, VerificationErrorCodeClaim)
}

func TestVerifyTypeMatchIsExact(t *testing.T) {
	signer := newTestSignerWithType(t, "at+jwt")
	compact := signer.sign(t, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	policy := ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		ExpectedType:      "at+jwt",
		AllowedAlgorithms: []Algorithm{ES256},
	}
	if _, err := signer.keySet.VerifyJWT(compact, policy); err != nil {
		t.Fatalf("exact typ match: %v", err)
	}

	policy.ExpectedType = "AT+JWT"
	_, err := signer.keySet.VerifyJWT(compact, policy)
	requireVerificationError(t, err, VerificationErrorCodeType)
}

func TestVerifyEmptyExpectedTypeRequiresAbsentType(t *testing.T) {
	now := time.Now()
	policy := ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []Algorithm{ES256},
	}

	withoutType := newTestSigner(t)
	compact := withoutType.sign(t, map[string]any{"exp": now.Add(time.Hour).Unix()})
	if _, err := withoutType.keySet.VerifyJWT(compact, policy); err != nil {
		t.Fatalf("token without typ: %v", err)
	}

	for _, typ := range []string{"JWT", "at+jwt"} {
		t.Run(typ, func(t *testing.T) {
			signer := newTestSignerWithType(t, typ)
			compact := signer.sign(t, map[string]any{"exp": now.Add(time.Hour).Unix()})
			requireVerificationError(t, func() error {
				_, err := signer.keySet.VerifyJWT(compact, policy)
				return err
			}(), VerificationErrorCodeType)
		})
	}
}

func TestTypeHeaderRejectsNonString(t *testing.T) {
	_, err := typeHeader(jose.Header{
		ExtraHeaders: map[jose.HeaderKey]any{jose.HeaderType: 42},
	})
	requireVerificationError(t, err, VerificationErrorCodeType)
}
