package jwt

import (
	jsonv2 "encoding/json/v2"
	"testing"
	"time"
)

func TestJWTTypesRoundTrip(t *testing.T) {
	type claims struct {
		NotBefore NumericDate `json:"nbf"`
		Audience  Audience    `json:"aud"`
	}

	issuedAt := time.Date(2026, time.August, 17, 12, 34, 56, 0, time.UTC)
	want := claims{NotBefore: NumericDate(issuedAt), Audience: Audience{"client"}}
	payload, err := jsonv2.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got, want := string(payload), `{"nbf":1786970096,"aud":"client"}`; got != want {
		t.Fatalf("Marshal() = %s, want %s", got, want)
	}

	var got claims
	if err := jsonv2.Unmarshal(payload, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !got.NotBefore.Time().Equal(want.NotBefore.Time()) {
		t.Errorf("NotBefore = %v, want %v", got.NotBefore.Time(), want.NotBefore.Time())
	}
	if !got.Audience.Contains("client") {
		t.Errorf("Audience = %v, want [client]", got.Audience)
	}

	if err := jsonv2.Unmarshal([]byte(`{"aud":["client","api"]}`), &got); err != nil {
		t.Fatalf("Unmarshal(array audience) error = %v", err)
	}
	if !got.Audience.Contains("client") || !got.Audience.Contains("api") {
		t.Errorf("Audience = %v, want [client api]", got.Audience)
	}
}
