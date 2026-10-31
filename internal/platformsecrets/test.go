package platformsecrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/tokencache"
)

const (
	issuer1         = "https://issuer1.test"
	issuer1ClientID = "clientID"
)

// TestStore runs TestCache, and checks that DPoP keys round trip through their
// handles.
func TestStore(t *testing.T, store tokencache.Store) {
	TestCache(t, store)

	handle, key, err := store.NewDPoPKey()
	if err != nil {
		t.Fatalf("NewDPoPKey: %v", err)
	}
	if len(handle) == 0 {
		t.Fatal("NewDPoPKey returned an empty handle")
	}
	if err := store.Set(issuer1, "dpop", &tokencache.Credential{Token: &oauth2.Token{AccessToken: "bound", TokenType: "DPoP"}, DPoPKey: handle}); err != nil {
		t.Fatal(err)
	}
	cred, err := store.Get(issuer1, "dpop")
	if err != nil {
		t.Fatal(err)
	}
	if cred == nil || cred.Token == nil || cred.Token.AccessToken != "bound" {
		t.Fatalf("unexpected credential %#v", cred)
	}
	loaded, err := store.LoadDPoPKey(cred.DPoPKey)
	if err != nil {
		t.Fatalf("LoadDPoPKey: %v", err)
	}
	created, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := jwt.NewSigningIdentity(loaded, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if created.Thumbprint() != reloaded.Thumbprint() {
		t.Fatal("loaded DPoP key differs from the created key")
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DPoP key is %T, want ECDSA", key.Public())
	}
	digest := sha256.Sum256([]byte("test"))
	sig, err := loaded.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing with loaded key: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature from loaded key did not verify")
	}
}

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

				if err := cache.Set(issuer1, issuer1ClientID, &tokencache.Credential{Token: token}); err != nil {
					return nil, err
				}

				return credToken(cache.Get(issuer1, issuer1ClientID))
			},
			want: (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"}),
		},
		{
			name: "cache miss by issuer",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer2.test", "clientID", &tokencache.Credential{Token: token}); err != nil {
					return nil, err
				}

				return credToken(cache.Get("https://issuer3.test", "clientID"))
			},
			want: nil,
		},
		{
			name: "cache miss by key",
			run: func(cache tokencache.CredentialCache) (*oauth2.Token, error) {
				token := (&oauth2.Token{AccessToken: "abc123"}).WithExtra(map[string]any{"id_token": "zyx987"})

				if err := cache.Set("https://issuer4.test", "clientID1", &tokencache.Credential{Token: token}); err != nil {
					return nil, err
				}

				return credToken(cache.Get("https://issuer4.test", "clientID2"))
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

func credToken(cred *tokencache.Credential, err error) (*oauth2.Token, error) {
	if err != nil || cred == nil {
		return nil, err
	}
	return cred.Token, nil
}
