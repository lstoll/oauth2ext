package dpop

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"testing"
	"time"
)

const (
	replayMethod = "POST"
	replayURI    = "https://example.test/token"
)

func replayValidator(t *testing.T, method string) *Validator {
	t.Helper()
	v, err := NewValidator(&ValidatorOpts{IgnoreThumbprint: true, ExpectedHTM: &method, ExpectedHTU: new(replayURI)})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fixedProof(t *testing.T, key crypto.Signer, jti string, issuedAt time.Time) string {
	t.Helper()
	return mustSignClaims(t, mustSigner(t, key), map[string]any{
		"jti": jti, "htm": replayMethod, "htu": replayURI, "iat": issuedAt.Unix(),
	}, dpopSignOpts())
}

func TestVerifierReplayProtection(t *testing.T) {
	key := generateTestKey(t)
	now := time.Now().Truncate(time.Second)
	compact := fixedProof(t, key, "same-jti", now)
	verifier := &Verifier{now: now}
	validator := replayValidator(t, replayMethod)
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); !errors.Is(err, ErrProofReplay) {
		t.Fatalf("second verification error = %v, want ErrProofReplay", err)
	}

	// Failed request-specific validation must not consume a proof.
	other := replayValidator(t, "GET")
	compact = fixedProof(t, key, "not-consumed", now)
	if _, err := verifier.VerifyAndDecode(compact, other); err == nil {
		t.Fatal("wrong htm accepted")
	}
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("proof rejected after failed validation: %v", err)
	}
}

func TestVerifierReplayCompositeKeyAndOptOut(t *testing.T) {
	const jti = "shared-jti"
	now := time.Now().Truncate(time.Second)
	first := generateTestKey(t)
	second := generateTestKey(t)
	validator := replayValidator(t, replayMethod)
	verifier := &Verifier{now: now}
	if _, err := verifier.VerifyAndDecode(fixedProof(t, first, jti, now), validator); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyAndDecode(fixedProof(t, second, jti, now), validator); err != nil {
		t.Fatalf("same jti from another key rejected: %v", err)
	}
	compact := fixedProof(t, first, "opt-out", now)
	noReplay := &Verifier{now: now, DisableReplayProtection: true}
	if _, err := noReplay.VerifyAndDecode(compact, validator); err != nil {
		t.Fatal(err)
	}
	if _, err := noReplay.VerifyAndDecode(compact, validator); err != nil {
		t.Fatalf("opt-out did not allow reuse: %v", err)
	}
}

func TestVerifierReplayConcurrentAndCapacity(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := generateTestKey(t)
	compact := fixedProof(t, key, "concurrent", now)
	verifier := &Verifier{now: now}
	validator := replayValidator(t, replayMethod)
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for range 16 {
		wg.Go(func() { _, err := verifier.VerifyAndDecode(compact, validator); results <- err })
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrProofReplay) {
			t.Fatalf("concurrent verification: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want 1", successes)
	}

	limited := &Verifier{now: now, ReplayCacheMaxEntries: 1}
	if _, err := limited.VerifyAndDecode(fixedProof(t, key, "first", now), validator); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.VerifyAndDecode(fixedProof(t, key, "second", now), validator); !errors.Is(err, ErrReplayStoreFull) {
		t.Fatalf("capacity error = %v, want ErrReplayStoreFull", err)
	}
}

func TestInMemoryReplayStoreExpiry(t *testing.T) {
	now := time.Unix(100, 0)
	store := newInMemoryReplayStore(1)
	store.now = func() time.Time { return now }
	until := now.Add(time.Minute)
	if err := store.CheckAndRecord(context.Background(), "key", "jti", until); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckAndRecord(context.Background(), "key", "jti", until); !errors.Is(err, ErrProofReplay) {
		t.Fatalf("replay error = %v", err)
	}
	now = until.Add(time.Nanosecond)
	if err := store.CheckAndRecord(context.Background(), "key", "jti", now.Add(time.Minute)); err != nil {
		t.Fatalf("reuse after expiry: %v", err)
	}
}

type failingReplayStore struct{ err error }

func (s failingReplayStore) CheckAndRecord(context.Context, string, string, time.Time) error {
	return s.err
}

func TestVerifierReplayStoreErrorFailsClosed(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := generateTestKey(t)
	want := errors.New("store unavailable")
	verifier := &Verifier{now: now, ReplayStore: failingReplayStore{want}}
	_, err := verifier.VerifyAndDecode(fixedProof(t, key, "store-error", now), replayValidator(t, replayMethod))
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want wrapped store error", err)
	}
}

type recordingReplayStore struct {
	thumbprint string
	jti        string
	until      time.Time
}

func (s *recordingReplayStore) CheckAndRecord(_ context.Context, thumbprint, jti string, until time.Time) error {
	s.thumbprint, s.jti, s.until = thumbprint, jti, until
	return nil
}

func TestVerifierReplayDeadline(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := generateTestKey(t)
	store := &recordingReplayStore{}
	verifier := &Verifier{now: now, ValidityAfterIssue: 10 * time.Minute, ClockSkew: time.Minute, ReplayStore: store}
	validator := replayValidator(t, replayMethod)
	if _, err := verifier.VerifyAndDecode(fixedProof(t, key, "validity-deadline", now), validator); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(11 * time.Minute); !store.until.Equal(want) {
		t.Fatalf("deadline = %s, want %s", store.until, want)
	}
	compact := mustSignClaims(t, mustSigner(t, key), map[string]any{
		"jti": "exp-deadline", "htm": replayMethod, "htu": replayURI, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	}, dpopSignOpts())
	if _, err := verifier.VerifyAndDecode(compact, validator); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(3 * time.Minute); !store.until.Equal(want) {
		t.Fatalf("capped deadline = %s, want %s", store.until, want)
	}
}
