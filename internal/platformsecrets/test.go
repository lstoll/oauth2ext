package platformsecrets

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/tokencache"
)

const (
	issuer1         = "https://issuer1.test"
	issuer1ClientID = "clientID"
)

func TestCache(t *testing.T, cache tokencache.CredentialCache) {
	for _, tc := range []struct {
		name string
		run  func(cache tokencache.CredentialCache) (*oauth2.Token, error)
		want *oauth2.Token
	}{
		{
			name: "happy path",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set(issuer1, issuer1ClientID, token); err != nil {
					return nil, err
				}

				return cache.Get(issuer1, issuer1ClientID)
			},
			want: (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"}),
		},
		{
			name: "cache miss by issuer",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer2.test", "clientID", token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer3.test", "clientID")
			},
			want: nil,
		},
		{
			name: "cache miss by key",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer4.test", "clientID1", token); err != nil {
					return nil, err
				}

				return cache.Get("https://issuer4.test", "clientID2")
			},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.run(cache)
			if err != nil {
				t.Fatal(err)
			}

			// ignore token internal state, it doesn't roundtrip in an
			// comparable way.
			// TODO(lstoll) better comparison?
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(oauth2.Token{})); diff != "" {
				t.Fatalf("want: %+v, got %+v", tc.want, got)
			}
		})
	}
}
