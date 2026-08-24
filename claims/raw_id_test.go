package claims

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
)

func TestRawIDRoundTrip(t *testing.T) {
	emailVerified := false
	issuedAt := time.Date(2026, time.August, 17, 12, 34, 56, 0, time.UTC)
	want := RawID{
		Issuer:        "https://issuer.example",
		Subject:       "subject",
		Audience:      jwt.Audience{"client"},
		IssuedAt:      jwt.NumericDate(issuedAt),
		EmailVerified: &emailVerified,
		Extra:         map[string]any{"groups": []string{"engineering"}},
	}

	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got RawID
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject {
		t.Errorf("issuer/subject = %q/%q, want %q/%q", got.Issuer, got.Subject, want.Issuer, want.Subject)
	}
	if !got.Audience.Contains("client") {
		t.Errorf("Audience = %v, want [client]", got.Audience)
	}
	if !got.IssuedAt.Time().Equal(want.IssuedAt.Time()) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt.Time(), want.IssuedAt.Time())
	}
	if got.EmailVerified == nil || *got.EmailVerified {
		t.Errorf("EmailVerified = %v, want false", got.EmailVerified)
	}
	if groups, ok := got.Extra["groups"].([]any); !ok || len(groups) != 1 || groups[0] != "engineering" {
		t.Errorf("Extra[groups] = %#v, want [engineering]", got.Extra["groups"])
	}
}

func TestRawIDRejectsDuplicateClaims(t *testing.T) {
	t.Run("input object", func(t *testing.T) {
		var id RawID
		err := json.Unmarshal([]byte(`{"sub":"first","sub":"second"}`), &id)
		if err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("Unmarshal() error = %v, want duplicate-name error", err)
		}
	})

	t.Run("extra typed claim", func(t *testing.T) {
		_, err := json.Marshal(RawID{Extra: map[string]any{"sub": "subject"}})
		if err == nil || !strings.Contains(err.Error(), `typed claim "sub"`) {
			t.Fatalf("Marshal() error = %v, want typed-claim error", err)
		}
	})
}
