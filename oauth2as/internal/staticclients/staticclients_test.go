package staticclients

import (
	"os"
	"slices"
	"testing"

	"github.com/lstoll/oauth2as"
)

func ptr[T any](v T) *T {
	return &v
}

func TestStaticClients(t *testing.T) {
	cb, err := os.ReadFile("testdata/clients.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		Name    string
		WithEnv map[string]string

		ClientID          string
		WantInvalidClient bool

		WantValidSecret   string
		WantInvalidSecret string

		WantRequiresPKCE *bool
	}{
		{
			Name:              "Valid simple client",
			ClientID:          "simple",
			WantValidSecret:   "secret",
			WantInvalidSecret: "othersecret",
		},
		{
			Name:              "Missing client ID",
			ClientID:          "not-in-file",
			WantInvalidClient: true,
		},
		{
			Name:             "Public client with localhost redirect and PKCE",
			ClientID:         "publocalpkce",
			WantValidSecret:  "", // empty secret should be fine
			WantRequiresPKCE: ptr(true),
		},
		{
			Name:            "Env secret, not set",
			ClientID:        "envsecret",
			WantValidSecret: "defaultsecret",
		},
		{
			Name: "Env secret, set",
			WithEnv: map[string]string{
				"SC_SECRET": "explicitsecret",
			},
			ClientID:        "envsecret",
			WantValidSecret: "explicitsecret",
		},
		{
			Name:              "Env secret, with simple secrets secret and redirect",
			ClientID:          "envsecret",
			WantValidSecret:   "defaultsecret",
			WantInvalidSecret: "secret", // valid for another client
		},
		{
			Name:              "Public client with localhost redirect and PKCE",
			ClientID:          "publocalpkceskip",
			WantInvalidSecret: "", // empty secret should not work
			WantRequiresPKCE:  ptr(false),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			for k, v := range tc.WithEnv {
				if err := os.Setenv(k, v); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Unsetenv(k) })
			}

			// after env set
			clients, err := ExpandUnmarshal(cb)
			if err != nil {
				t.Fatal(err)
			}

			valid, err := clients.IsValidClientID(t.Context(), tc.ClientID)
			if err != nil {
				// we never error
				t.Fatal(err)
			}

			if tc.WantInvalidClient {
				// different tests here, everything should error and we should
				// bail.
				if valid {
					t.Error("client should not be valid but is")
				}

				if _, err := clients.ClientOpts(t.Context(), tc.ClientID); err == nil {
					t.Error("Client opts check should fail")
				}

				if _, err := clients.ValidateClientSecret(t.Context(), tc.ClientID, ""); err == nil {
					t.Error("client secret check should fail")
				}

				if _, err := clients.RedirectURIs(t.Context(), tc.ClientID); err == nil {
					t.Error("client redirect uri check should fail")
				}

				return
			}

			if !valid {
				t.Errorf("client %s should be valid", tc.ClientID)
			}

			opts, err := clients.ClientOpts(t.Context(), tc.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			// Test PKCE requirements only if WantRequiresPKCE is explicitly set
			if tc.WantRequiresPKCE != nil {
				hasSkipPKCE := slices.Contains(opts, oauth2as.ClientOptSkipPKCE)
				requiresPKCE := !hasSkipPKCE
				if *tc.WantRequiresPKCE != requiresPKCE {
					t.Errorf("want requires PKCE %t, got requires PKCE %t (has skip-pkce option: %t)", *tc.WantRequiresPKCE, requiresPKCE, hasSkipPKCE)
				}
			}

			if tc.WantValidSecret != "" {
				valid, err := clients.ValidateClientSecret(t.Context(), tc.ClientID, tc.WantValidSecret)
				if err != nil {
					t.Fatal(err)
				}
				if !valid {
					t.Errorf("want secret %s to be valid, but it was not", tc.WantValidSecret)
				}
			}
			if tc.WantInvalidSecret != "" {
				valid, err := clients.ValidateClientSecret(t.Context(), tc.ClientID, tc.WantInvalidSecret)
				if err != nil {
					t.Fatal(err)
				}
				if valid {
					t.Errorf("want secret %s to be invalid, but it was", tc.WantInvalidSecret)
				}
			}
		})
	}
}
