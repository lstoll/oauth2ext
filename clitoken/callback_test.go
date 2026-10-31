package clitoken

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oauth2client"
)

type openerFunc func(context.Context, string) error

func (f openerFunc) Open(ctx context.Context, target string) error { return f(ctx, target) }

// callback sends params to the flow's callback URL and returns the status.
func callback(ctx context.Context, authURL string, params url.Values) (int, error) {
	auth, err := url.Parse(authURL)
	if err != nil {
		return 0, err
	}
	cb, err := url.Parse(auth.Query().Get("redirect_uri"))
	if err != nil {
		return 0, err
	}
	cb.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cb.String(), nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func TestCallbackWithWrongStateDoesNotEndLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	var statuses []int
	cfg := Config{
		ClientType:   oauth2client.PublicClient,
		OAuth2Client: &oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
		Opener: openerFunc(func(ctx context.Context, target string) error {
			for _, params := range []url.Values{
				{"state": {"wrong-state"}, "error": {"access_denied"}},
				{"error": {"access_denied"}},
				{"state": {"wrong-state"}, "code": {"1234"}},
				{"state": {"wrong-state"}, "error": {"access_denied"}},
			} {
				status, err := callback(ctx, target, params)
				if err != nil {
					return err
				}
				statuses = append(statuses, status)
			}
			return nil
		}),
	}
	source, err := cfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// With no valid callback, the login waits until the caller cancels it.
	if _, err := source.Token(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unrelated callback ended login: %v", err)
	}
	for i, status := range statuses {
		if status != http.StatusBadRequest {
			t.Errorf("callback %d: status %d, want 400", i, status)
		}
	}
}

func TestCallbackErrorWithStateEndsLoginOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var second int
	cfg := Config{
		ClientType:   oauth2client.PublicClient,
		OAuth2Client: &oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
		Opener: openerFunc(func(ctx context.Context, target string) error {
			auth, err := url.Parse(target)
			if err != nil {
				return err
			}
			params := url.Values{"state": {auth.Query().Get("state")}, "error": {"access_denied"}}
			if _, err := callback(ctx, target, params); err != nil {
				return err
			}
			// A repeat must not block on the result channel.
			second, err = callback(ctx, target, params)
			return err
		}),
	}
	source, err := cfg.TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Token(); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want access_denied error, got %v", err)
	}
	if second != http.StatusBadRequest {
		t.Fatalf("repeated callback status %d, want 400", second)
	}
}
