package tokencache

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

var _ oauth2.TokenSource = (*staticTokenSource)(nil)

type staticTokenSource struct {
	token string
}

type mockTokenSource struct {
	token     string
	callCount int
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	m.callCount++
	return &oauth2.Token{
		AccessToken: m.token,
		Expiry:      time.Now().Add(1 * time.Minute),
	}, nil
}

type memCache struct {
	cache map[string]oauth2.Token
}

var _ CredentialCache = &memCache{}

func (m *memCache) Get(issuer, key string) (*Credential, error) {
	v, ok := m.cache[issuer+key]
	if ok {
		return &Credential{Token: &v}, nil
	}
	return nil, nil
}

func (m *memCache) Set(issuer, key string, cred *Credential) error {
	m.cache[issuer+key] = *cred.Token
	return nil
}

func (m *memCache) Available() bool {
	return true
}

func (s *staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: s.token,
		Expiry:      time.Now().Add(1 * time.Minute),
	}, nil
}

func TestCacheTokenSource(t *testing.T) {
	tests := []struct {
		name        string
		setupCache  func(*memCache)
		earlyExpiry time.Duration
		wantToken   string
		wantCached  bool // whether we expect the token to come from cache vs wrapped source
	}{
		{
			name: "no cached token - fetches from wrapped source",
			setupCache: func(cache *memCache) {
				// No token in cache
			},
			earlyExpiry: DefaultEarlyExpiry,
			wantToken:   "fresh_token",
			wantCached:  false,
		},
		{
			name: "valid cached token - returns cached token",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "cached_token",
					Expiry:      time.Now().Add(2 * time.Minute),
				}
			},
			earlyExpiry: DefaultEarlyExpiry,
			wantToken:   "cached_token",
			wantCached:  true,
		},
		{
			name: "expired cached token - fetches from wrapped source",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "expired_token",
					Expiry:      time.Now().Add(-1 * time.Minute),
				}
			},
			earlyExpiry: DefaultEarlyExpiry,
			wantToken:   "fresh_token",
			wantCached:  false,
		},
		{
			name: "token within grace period - fetches from wrapped source",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "grace_period_token",
					Expiry:      time.Now().Add(15 * time.Second),
				}
			},
			earlyExpiry: DefaultEarlyExpiry,
			wantToken:   "fresh_token",
			wantCached:  false,
		},
		{
			name: "token outside grace period - returns cached token",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "valid_token",
					Expiry:      time.Now().Add(45 * time.Second),
				}
			},
			earlyExpiry: DefaultEarlyExpiry,
			wantToken:   "valid_token",
			wantCached:  true,
		},
		{
			name: "custom grace period - token within custom grace period",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "custom_grace_token",
					Expiry:      time.Now().Add(10 * time.Second),
				}
			},
			earlyExpiry: 20 * time.Second,
			wantToken:   "fresh_token",
			wantCached:  false,
		},
		{
			name: "custom grace period - token outside custom grace period",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "custom_valid_token",
					Expiry:      time.Now().Add(30 * time.Second),
				}
			},
			earlyExpiry: 20 * time.Second,
			wantToken:   "custom_valid_token",
			wantCached:  true,
		},
		{
			name: "zero grace period defaults to default grace period",
			setupCache: func(cache *memCache) {
				cache.cache["https://issuerclient"] = oauth2.Token{
					AccessToken: "zero_grace_token",
					Expiry:      time.Now().Add(1 * time.Second),
				}
			},
			earlyExpiry: 0,
			wantToken:   "fresh_token",
			wantCached:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &memCache{cache: make(map[string]oauth2.Token)}
			tt.setupCache(cache)

			mockSource := &mockTokenSource{token: "fresh_token"}

			cfg := Config{
				Issuer:        "https://issuer",
				CacheKey:      "client",
				WrappedSource: mockSource,
				Cache:         cache,
				EarlyExpiry:   tt.earlyExpiry,
			}

			ts, err := cfg.TokenSource(context.TODO())
			if err != nil {
				t.Fatal(err)
			}

			// Reset call count before getting token
			mockSource.callCount = 0

			gotTok, err := ts.Token()
			if err != nil {
				t.Fatal(err)
			}

			if gotTok.AccessToken != tt.wantToken {
				t.Errorf("got token %q, want %q", gotTok.AccessToken, tt.wantToken)
			}

			// Verify cache behavior by checking if wrapped source was called
			// If we expect cached token, wrapped source should not be called
			// If we expect fresh token, wrapped source should be called
			if tt.wantCached && mockSource.callCount > 0 {
				t.Errorf("expected cached token but wrapped source was called %d times", mockSource.callCount)
			} else if !tt.wantCached && mockSource.callCount == 0 {
				t.Error("expected fresh token but wrapped source was not called")
			}
		})
	}
}
