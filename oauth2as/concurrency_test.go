package oauth2as

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"lds.li/oauth2ext/oauth2as/internal/token"
)

func TestRefreshTokenConcurrency(t *testing.T) {
	s := NewMemStorage()
	signer, verifier := testSignerVerifier(t)

	srv := &Server{
		config: Config{
			Issuer:   "https://issuer",
			Storage:  s,
			Signer:   signer,
			Verifier: verifier,
			TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
			Clients: staticClientSource{
				{
					ID:           "test-client",
					Secrets:      []string{"test-secret"},
					RedirectURLs: []string{"https://redirect"},
				},
			},
			RefreshTokenRotationGracePeriod: 30 * time.Second,
		},
		now:    time.Now,
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	srv.config.RefreshTokenRotationGracePeriod = 1 * time.Minute

	userID := "test-user"
	grant := &StoredGrant{
		UserID:        userID,
		ClientID:      "test-client",
		GrantedScopes: []string{"openid", "offline_access"},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	gid, err := srv.config.Storage.CreateGrant(context.Background(), grant)
	if err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}

	tok := token.New(tokenUsageRefresh, gid, userID)
	rtID := "rt-1"
	rt := &StoredRefreshToken{
		GrantID:          gid,
		Token:            tok.Stored(),
		ValidUntil:       time.Now().Add(1 * time.Hour),
		StorageExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := srv.config.Storage.CreateRefreshToken(context.Background(), rtID, rt); err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	rtString := tok.ToUser(rtID)

	// Fire concurrent requests
	var wg sync.WaitGroup
	concurrency := 10
	results := make(chan int, concurrency)

	for range concurrency {
		wg.Go(func() {
			v := url.Values{}
			v.Set("grant_type", "refresh_token")
			v.Set("refresh_token", rtString)
			v.Set("client_id", "test-client")

			req := httptest.NewRequest("POST", "/token", nil)
			req.Form = v

			w := httptest.NewRecorder()
			srv.TokenHandler(w, req)

			results <- w.Code
		})
	}

	wg.Wait()
	close(results)

	successCount := 0
	failureCount := 0

	for code := range results {
		if code == http.StatusOK {
			successCount++
		} else {
			failureCount++
		}
	}

	// 1 will happen if the first completes before the second starts, and 0 if
	// they happen truly concurrently.
	if successCount > 1 {
		t.Errorf("concurrent updates with the same token should never succeed more than once")
	}

	// in all cases the grant should be expired due to excessive refresh token
	// replay
	postGrant, err := s.GetGrant(t.Context(), gid)
	if err == nil || postGrant != nil {
		t.Errorf("grant not expired")
	}
}
