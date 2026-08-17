package jwt

import (
	jsonv2 "encoding/json/v2"
	"testing"
	"time"
)

func TestJWTTimeRoundTrip(t *testing.T) {
	type claims struct {
		IssuedAt time.Time  `json:"iat"`
		Expiry   *time.Time `json:"exp"`
	}

	issuedAt := time.Date(2026, time.August, 17, 12, 34, 56, 0, time.UTC)
	expiry := issuedAt.Add(time.Hour)
	want := claims{IssuedAt: issuedAt, Expiry: &expiry}

	payload, err := jsonv2.Marshal(want, jsonv2.WithMarshalers(JWTMarshalers))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got, want := string(payload), `{"iat":1786970096,"exp":1786973696}`; got != want {
		t.Fatalf("Marshal() = %s, want %s", got, want)
	}

	var got claims
	if err := jsonv2.Unmarshal(payload, &got, jsonv2.WithUnmarshalers(JWTUnmarshalers)); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("IssuedAt = %v, want %v", got.IssuedAt, want.IssuedAt)
	}
	if got.Expiry == nil || !got.Expiry.Equal(*want.Expiry) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, want.Expiry)
	}
}
