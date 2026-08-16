package jwt

import (
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"
)

func testClaims(audiences []string, now time.Time, custom map[string]any) map[string]any {
	out := map[string]any{
		"iss": "https://issuer.example",
		"sub": "subject",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if len(audiences) == 1 {
		out["aud"] = audiences[0]
	} else if len(audiences) > 1 {
		out["aud"] = append([]string(nil), audiences...)
	}
	maps.Copy(out, custom)
	return out
}

func TestVerifierClonesPolicySlices(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, testClaims([]string{"client"}, now, nil))
	audiences := []string{"client"}
	algorithms := []Algorithm{ES256}
	verifier, err := NewVerifier(signer.keySet, ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		ExpectedAudiences: audiences,
		AllowedAlgorithms: algorithms,
		Type:              TypeAny,
		RequireIssuedAt:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	audiences[0] = "attacker"
	algorithms[0] = RS256
	if _, err := verifier.Verify(compact); err != nil {
		t.Fatalf("verifier changed after source policy mutation: %v", err)
	}
}

func TestVerifyAudienceAndTime(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, testClaims([]string{"client"}, now, nil))

	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		ExpectedAudiences: []string{"client"},
		AllowedAlgorithms: []Algorithm{ES256},
		Type:              TypeAny,
		RequireIssuedAt:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	iss, err := verified.Issuer()
	if err != nil {
		t.Fatal(err)
	}
	if iss != "https://issuer.example" {
		t.Fatalf("issuer: %q", iss)
	}
	algorithm, err := verified.Algorithm()
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != ES256 {
		t.Fatalf("algorithm: got %q, want ES256", algorithm)
	}
	var decoded struct {
		Subject string `json:"sub"`
		Issuer  string `json:"iss"`
	}
	if err := verified.DecodeClaims(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Subject != "subject" || decoded.Issuer != "https://issuer.example" {
		t.Fatalf("decoded claims: %+v", decoded)
	}
	if err := verified.DecodeClaims(nil); err == nil {
		t.Fatal("DecodeClaims accepted nil destination")
	}
	if _, err := verified.String("missing"); err == nil {
		t.Fatal("expected missing claim error")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, testClaims([]string{"other"}, now, nil))
	_, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		ExpectedAudiences: []string{"client"},
		AllowedAlgorithms: []Algorithm{ES256},
		Type:              TypeAny,
	})
	if err == nil {
		t.Fatal("expected audience error")
	}
}

func TestVerifyClassifiesDisallowedAlgorithm(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{"sub": "subject"})
	_, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES384},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	requireVerificationError(t, err, VerificationErrorCodeInvalidAlgorithm)
}

func TestVerifyRejectsOutOfRangeNumericDate(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{
		"nbf": json.Number("1e20"),
	})
	_, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES256},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	requireVerificationError(t, err, VerificationErrorCodeClaim)
}

func TestVerifyRejectsAmbiguousJSON(t *testing.T) {
	signer := newTestSigner(t)
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "duplicate registered claim",
			payload: []byte(`{"sub":"alice","sub":"bob"}`),
		},
		{
			name:    "nested duplicate claim",
			payload: []byte(`{"custom":{"role":"reader","role":"admin"}}`),
		},
		{
			name:    "invalid UTF-8",
			payload: []byte{'{', '"', 's', 'u', 'b', '"', ':', '"', 0xff, '"', '}'},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compact := signer.signRaw(t, tt.payload)
			_, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
				IgnoreIssuer:           true,
				IgnoreAudiences:        true,
				AllowedAlgorithms:      []Algorithm{ES256},
				Type:                   TypeAny,
				AllowMissingExpiration: true,
			})
			requireVerificationError(t, err, VerificationErrorCodeInvalidToken)
		})
	}
}

func TestVerifiedJWTRejectsNullTypedClaim(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{"custom": nil})
	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES256},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Has("custom") {
		t.Fatal("null claim should still be present")
	}
	if !verified.HasNull("custom") {
		t.Fatal("expected null claim")
	}
	if verified.HasString("custom") {
		t.Fatal("null claim must not be treated as a string")
	}
	if _, err := verified.String("custom"); !errors.Is(err, ErrClaim) {
		t.Fatalf("error: got %v, want ErrClaim", err)
	}
}

func TestVerifiedJWTGenericAccessors(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, testClaims([]string{"client"}, now, map[string]any{
		"org_id": "org-1",
		"admin":  true,
	}))
	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		ExpectedIssuer:    "https://issuer.example",
		ExpectedAudiences: []string{"client"},
		AllowedAlgorithms: []Algorithm{ES256},
		Type:              TypeAny,
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := verified.String("org_id")
	if err != nil || org != "org-1" {
		t.Fatalf("org_id: %q %v", org, err)
	}
	admin, err := verified.Bool("admin")
	if err != nil || !admin {
		t.Fatalf("admin: %v %v", admin, err)
	}
}

func TestVerifiedJWTObjectReturnsCopy(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{
		"settings": map[string]any{
			"theme":  "dark",
			"nested": map[string]any{"enabled": true},
		},
	})
	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES256},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	settings, err := verified.Object("settings")
	if err != nil {
		t.Fatal(err)
	}
	settings["theme"] = "light"
	settings["nested"].(map[string]any)["enabled"] = false

	again, err := verified.Object("settings")
	if err != nil {
		t.Fatal(err)
	}
	if again["theme"] != "dark" || again["nested"].(map[string]any)["enabled"] != true {
		t.Fatalf("object mutation changed verified claims: %#v", again)
	}
}

func TestVerifiedJWTArrayOfJSONValues(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{
		"roles": []map[string]any{{"name": "admin"}},
		"empty": []any{},
	})
	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES256},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !verified.HasArray("roles") || !verified.HasArrayOf[map[string]any]("roles") {
		t.Fatal("expected array of objects")
	}
	if verified.HasArrayOf[string]("roles") {
		t.Fatal("object array reported as string array")
	}
	roles, err := verified.ArrayOf[map[string]any]("roles")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0]["name"] != "admin" {
		t.Fatalf("roles: got %#v", roles)
	}
	roles[0]["name"] = "reader"
	again, err := verified.ArrayOf[map[string]any]("roles")
	if err != nil {
		t.Fatal(err)
	}
	if again[0]["name"] != "admin" {
		t.Fatalf("array mutation changed verified claims: %#v", again)
	}
	if !verified.HasArrayOf[string]("empty") {
		t.Fatal("empty array should satisfy ArrayOf[string]")
	}
	empty, err := verified.ArrayOf[string]("empty")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty array: got %v, %v", empty, err)
	}
}

func TestVerifiedJWTNumbersUseFloat64(t *testing.T) {
	signer := newTestSigner(t)
	compact := signer.sign(t, map[string]any{
		"large": json.Number("9007199254740993"),
		"object": map[string]any{
			"large": json.Number("9007199254740993"),
		},
	})
	verified, err := verifyJWT(t, signer.keySet, compact, ValidationPolicy{
		IgnoreIssuer:           true,
		IgnoreAudiences:        true,
		AllowedAlgorithms:      []Algorithm{ES256},
		Type:                   TypeAny,
		AllowMissingExpiration: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := verified.Number("large")
	if err != nil {
		t.Fatal(err)
	}
	want := float64(9_007_199_254_740_993)
	if n != want {
		t.Fatalf("number: got %v want %v", n, want)
	}
	object, err := verified.Object("object")
	if err != nil {
		t.Fatal(err)
	}
	objectNumber, ok := object["large"].(float64)
	if !ok || objectNumber != want {
		t.Fatalf("object number: got %#v", object["large"])
	}
}
