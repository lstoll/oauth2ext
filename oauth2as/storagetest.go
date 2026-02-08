package oauth2as

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestStorage runs a comprehensive test suite against a Storage implementation.
// Implementations can call this from their own packages to verify compliance.
//
// The factory function is invoked at the start of each subtest to provide a fresh
// Storage instance, ensuring tests do not interfere with each other.
func TestStorage(t *testing.T, factory func() Storage) {
	ctx := context.Background()

	t.Run("CreateGrant_roundtrip", func(t *testing.T) {
		s := factory()
		want := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid", "profile"},
			Request: &AuthRequest{
				ClientID:    "client-1",
				RedirectURI: "https://redirect",
				State:       "s1",
				Scopes:      []string{"openid"},
			},
			GrantedAt:         time.Now().Truncate(time.Millisecond),
			ExpiresAt:         time.Now().Add(time.Hour).Truncate(time.Millisecond),
			AdditionalState:   json.RawMessage(`{"dpopThumbprint":"tp1"}`),
			Metadata:          []byte("metadata"),
			EncryptedMetadata: []byte("encrypted"),
			Version:           0,
		}

		id, err := s.CreateGrant(ctx, want)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}
		if id == "" {
			t.Fatal("CreateGrant: expected non-empty ID")
		}

		got, err := s.GetGrant(ctx, id)
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}

		if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("grant roundtrip mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("GetGrant_notFound", func(t *testing.T) {
		s := factory()
		_, err := s.GetGrant(ctx, "nonexistent-id")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetGrant: want ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateGrant_roundtrip", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		id, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		got, err := s.GetGrant(ctx, id)
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}

		got.GrantedScopes = []string{"openid", "email"}
		got.Metadata = []byte("updated-metadata")
		versionBeforeUpdate := got.Version

		if err := s.UpdateGrant(ctx, id, got); err != nil {
			t.Fatalf("UpdateGrant: %v", err)
		}

		got2, err := s.GetGrant(ctx, id)
		if err != nil {
			t.Fatalf("GetGrant after update: %v", err)
		}

		if diff := cmp.Diff(got.GrantedScopes, got2.GrantedScopes); diff != "" {
			t.Errorf("GrantedScopes mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(got.Metadata, got2.Metadata); diff != "" {
			t.Errorf("Metadata mismatch (-want +got):\n%s", diff)
		}
		if got2.Version != versionBeforeUpdate+1 {
			t.Errorf("Version: want %d, got %d", versionBeforeUpdate+1, got2.Version)
		}
	})

	t.Run("UpdateGrant_concurrentUpdate", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		id, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		// Update with wrong version
		staleGrant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid", "stale"},
			GrantedAt:     grant.GrantedAt,
			ExpiresAt:     grant.ExpiresAt,
			Version:       999, // wrong version
		}

		err = s.UpdateGrant(ctx, id, staleGrant)
		if !errors.Is(err, ErrConcurrentUpdate) {
			t.Errorf("UpdateGrant: want ErrConcurrentUpdate, got %v", err)
		}
	})

	t.Run("UpdateGrant_conflictingUpdates", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		id, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		var fetchReady sync.WaitGroup
		fetchReady.Add(2)

		var result1, result2 error
		var grant1, grant2 *StoredGrant

		// Both must complete GetGrant before either calls UpdateGrant
		start := make(chan struct{})

		go func() {
			defer wg.Done()
			g, err := s.GetGrant(ctx, id)
			if err != nil {
				result1 = err
				fetchReady.Done()
				return
			}
			grant1 = g
			grant1.Metadata = []byte("update-from-goroutine-1")
			fetchReady.Done()
			<-start
			result1 = s.UpdateGrant(ctx, id, grant1)
		}()

		go func() {
			defer wg.Done()
			g, err := s.GetGrant(ctx, id)
			if err != nil {
				result2 = err
				fetchReady.Done()
				return
			}
			grant2 = g
			grant2.Metadata = []byte("update-from-goroutine-2")
			fetchReady.Done()
			<-start
			result2 = s.UpdateGrant(ctx, id, grant2)
		}()

		fetchReady.Wait() // both have fetched the same version
		close(start)      // release both to race on UpdateGrant
		wg.Wait()

		// Exactly one should succeed, one should get ErrConcurrentUpdate
		success1 := result1 == nil
		success2 := result2 == nil
		if success1 == success2 {
			t.Errorf("expected exactly one update to succeed: result1=%v, result2=%v", result1, result2)
		}

		concurrentErr := result1
		if success1 {
			concurrentErr = result2
		}
		if !errors.Is(concurrentErr, ErrConcurrentUpdate) {
			t.Errorf("losing update: want ErrConcurrentUpdate, got %v", concurrentErr)
		}

		// Verify the winner's data was persisted
		final, err := s.GetGrant(ctx, id)
		if err != nil {
			t.Fatalf("GetGrant: %v", err)
		}
		winnerMetadata := grant1.Metadata
		if success2 {
			winnerMetadata = grant2.Metadata
		}
		if diff := cmp.Diff(winnerMetadata, final.Metadata); diff != "" {
			t.Errorf("stored grant should reflect winner's update (-want +got):\n%s", diff)
		}
	})

	t.Run("UpdateGrant_notFound", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		err := s.UpdateGrant(ctx, "nonexistent-id", grant)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("UpdateGrant: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireGrant_removesGrant", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		id, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		if err := s.ExpireGrant(ctx, id); err != nil {
			t.Fatalf("ExpireGrant: %v", err)
		}

		_, err = s.GetGrant(ctx, id)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetGrant after ExpireGrant: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireGrant_idempotentForNonexistent", func(t *testing.T) {
		s := factory()
		if err := s.ExpireGrant(ctx, "nonexistent-id"); err != nil {
			t.Errorf("ExpireGrant for nonexistent: want nil, got %v", err)
		}
	})

	t.Run("CreateAuthCode_roundtrip", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		codeID := "code-1"
		wantCode := &StoredAuthCode{
			Code:              []byte("code-bytes"),
			GrantID:           grantID,
			ValidUntil:        time.Now().Add(5 * time.Minute).Truncate(time.Millisecond),
			StorageExpiresAt:  time.Now().Add(10 * time.Minute).Truncate(time.Millisecond),
			EncryptedGrantKey: []byte("encrypted-key"),
			Version:           0,
		}

		if err := s.CreateAuthCode(ctx, codeID, wantCode); err != nil {
			t.Fatalf("CreateAuthCode: %v", err)
		}

		gotCode, gotGrant, err := s.GetAuthCodeAndGrant(ctx, codeID)
		if err != nil {
			t.Fatalf("GetAuthCodeAndGrant: %v", err)
		}

		if diff := cmp.Diff(wantCode, gotCode, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("auth code roundtrip mismatch (-want +got):\n%s", diff)
		}
		if gotGrant == nil || gotGrant.UserID != "user-1" {
			t.Errorf("GetAuthCodeAndGrant: grant mismatch, got %+v", gotGrant)
		}
		if gotCode.GrantID != grantID {
			t.Errorf("auth code GrantID: want %q, got %q", grantID, gotCode.GrantID)
		}
	})

	t.Run("GetAuthCodeAndGrant_notFound", func(t *testing.T) {
		s := factory()
		_, _, err := s.GetAuthCodeAndGrant(ctx, "nonexistent-code-id")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetAuthCodeAndGrant: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireAuthCode_removesCode", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		codeID := "code-to-expire"
		code := &StoredAuthCode{
			Code:             []byte("code"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(5 * time.Minute),
			StorageExpiresAt: time.Now().Add(10 * time.Minute),
		}

		if err := s.CreateAuthCode(ctx, codeID, code); err != nil {
			t.Fatalf("CreateAuthCode: %v", err)
		}

		if err := s.ExpireAuthCode(ctx, codeID); err != nil {
			t.Fatalf("ExpireAuthCode: %v", err)
		}

		_, _, err = s.GetAuthCodeAndGrant(ctx, codeID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetAuthCodeAndGrant after ExpireAuthCode: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireAuthCode_notFound", func(t *testing.T) {
		s := factory()
		err := s.ExpireAuthCode(ctx, "nonexistent-code-id")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("ExpireAuthCode: want ErrNotFound, got %v", err)
		}
	})

	t.Run("CreateRefreshToken_roundtrip", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid", "offline_access"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		tokenID := "rt-1"
		wantToken := &StoredRefreshToken{
			Token:             []byte("token-bytes"),
			GrantID:           grantID,
			ValidUntil:        time.Now().Add(24 * time.Hour).Truncate(time.Millisecond),
			StorageExpiresAt:  time.Now().Add(48 * time.Hour).Truncate(time.Millisecond),
			ReplacedByTokenID: "",
			EncryptedGrantKey: []byte("encrypted-key"),
			Version:           0,
		}

		if err := s.CreateRefreshToken(ctx, tokenID, wantToken); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		gotToken, gotGrant, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
		if err != nil {
			t.Fatalf("GetRefreshTokenAndGrant: %v", err)
		}

		if diff := cmp.Diff(wantToken, gotToken, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("refresh token roundtrip mismatch (-want +got):\n%s", diff)
		}
		if gotGrant == nil || gotGrant.UserID != "user-1" {
			t.Errorf("GetRefreshTokenAndGrant: grant mismatch, got %+v", gotGrant)
		}
		if gotToken.GrantID != grantID {
			t.Errorf("refresh token GrantID: want %q, got %q", grantID, gotToken.GrantID)
		}
	})

	t.Run("UpdateRefreshToken_roundtrip", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		tokenID := "rt-update"
		token := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
			Version:          0,
		}

		if err := s.CreateRefreshToken(ctx, tokenID, token); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		gotToken, _, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
		if err != nil {
			t.Fatalf("GetRefreshTokenAndGrant: %v", err)
		}

		gotToken.ReplacedByTokenID = "rt-rotated"
		gotToken.ValidUntil = time.Now().Add(2 * time.Hour)
		versionBeforeUpdate := gotToken.Version

		if err := s.UpdateRefreshToken(ctx, tokenID, gotToken); err != nil {
			t.Fatalf("UpdateRefreshToken: %v", err)
		}

		gotToken2, _, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
		if err != nil {
			t.Fatalf("GetRefreshTokenAndGrant after update: %v", err)
		}

		if gotToken2.ReplacedByTokenID != "rt-rotated" {
			t.Errorf("ReplacedByTokenID: want %q, got %q", "rt-rotated", gotToken2.ReplacedByTokenID)
		}
		if gotToken2.Version != versionBeforeUpdate+1 {
			t.Errorf("Version: want %d, got %d", versionBeforeUpdate+1, gotToken2.Version)
		}
	})

	t.Run("UpdateRefreshToken_concurrentUpdate", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		tokenID := "rt-concurrent"
		token := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
			Version:          0,
		}

		if err := s.CreateRefreshToken(ctx, tokenID, token); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		staleToken := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
			Version:          999, // wrong version
		}

		err = s.UpdateRefreshToken(ctx, tokenID, staleToken)
		if !errors.Is(err, ErrConcurrentUpdate) {
			t.Errorf("UpdateRefreshToken: want ErrConcurrentUpdate, got %v", err)
		}
	})

	t.Run("UpdateRefreshToken_conflictingUpdates", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		tokenID := "rt-conflict"
		token := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
			Version:          0,
		}

		if err := s.CreateRefreshToken(ctx, tokenID, token); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		var fetchReady sync.WaitGroup
		fetchReady.Add(2)

		var result1, result2 error
		var token1, token2 *StoredRefreshToken

		start := make(chan struct{})

		go func() {
			defer wg.Done()
			tok, _, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
			if err != nil {
				result1 = err
				fetchReady.Done()
				return
			}
			token1 = tok
			token1.ReplacedByTokenID = "rotated-by-1"
			fetchReady.Done()
			<-start
			result1 = s.UpdateRefreshToken(ctx, tokenID, token1)
		}()

		go func() {
			defer wg.Done()
			tok, _, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
			if err != nil {
				result2 = err
				fetchReady.Done()
				return
			}
			token2 = tok
			token2.ReplacedByTokenID = "rotated-by-2"
			fetchReady.Done()
			<-start
			result2 = s.UpdateRefreshToken(ctx, tokenID, token2)
		}()

		fetchReady.Wait() // both have fetched the same version
		close(start)
		wg.Wait()

		success1 := result1 == nil
		success2 := result2 == nil
		if success1 == success2 {
			t.Errorf("expected exactly one update to succeed: result1=%v, result2=%v", result1, result2)
		}

		concurrentErr := result1
		if success1 {
			concurrentErr = result2
		}
		if !errors.Is(concurrentErr, ErrConcurrentUpdate) {
			t.Errorf("losing update: want ErrConcurrentUpdate, got %v", concurrentErr)
		}

		final, _, err := s.GetRefreshTokenAndGrant(ctx, tokenID)
		if err != nil {
			t.Fatalf("GetRefreshTokenAndGrant: %v", err)
		}
		winnerReplacedBy := token1.ReplacedByTokenID
		if success2 {
			winnerReplacedBy = token2.ReplacedByTokenID
		}
		if final.ReplacedByTokenID != winnerReplacedBy {
			t.Errorf("stored token ReplacedByTokenID: want %q, got %q", winnerReplacedBy, final.ReplacedByTokenID)
		}
	})

	t.Run("UpdateRefreshToken_notFound", func(t *testing.T) {
		s := factory()
		token := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          "grant-id",
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
			Version:          0,
		}

		err := s.UpdateRefreshToken(ctx, "nonexistent-token-id", token)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("UpdateRefreshToken: want ErrNotFound, got %v", err)
		}
	})

	t.Run("GetRefreshTokenAndGrant_notFound", func(t *testing.T) {
		s := factory()
		_, _, err := s.GetRefreshTokenAndGrant(ctx, "nonexistent-token-id")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetRefreshTokenAndGrant: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireRefreshToken_removesToken", func(t *testing.T) {
		s := factory()
		grant := &StoredGrant{
			UserID:        "user-1",
			ClientID:      "client-1",
			GrantedScopes: []string{"openid"},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(time.Hour),
			Version:       0,
		}

		grantID, err := s.CreateGrant(ctx, grant)
		if err != nil {
			t.Fatalf("CreateGrant: %v", err)
		}

		tokenID := "rt-to-expire"
		token := &StoredRefreshToken{
			Token:            []byte("token"),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(time.Hour),
			StorageExpiresAt: time.Now().Add(2 * time.Hour),
		}

		if err := s.CreateRefreshToken(ctx, tokenID, token); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		if err := s.ExpireRefreshToken(ctx, tokenID); err != nil {
			t.Fatalf("ExpireRefreshToken: %v", err)
		}

		_, _, err = s.GetRefreshTokenAndGrant(ctx, tokenID)
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("GetRefreshTokenAndGrant after ExpireRefreshToken: want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExpireRefreshToken_notFound", func(t *testing.T) {
		s := factory()
		err := s.ExpireRefreshToken(ctx, "nonexistent-token-id")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("ExpireRefreshToken: want ErrNotFound, got %v", err)
		}
	})
}
