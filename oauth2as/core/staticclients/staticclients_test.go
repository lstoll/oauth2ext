package staticclients

import (
	"os"
	"testing"
)

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

		WantValidRedirect   string
		WantInvalidRedirect string

		WantValidSecret   string
		WantInvalidSecret string

		WantRequiresPKCE bool
	}{
		{
			Name:                "Valid simple client",
			ClientID:            "simple",
			WantValidRedirect:   "http://myserver.com",
			WantInvalidRedirect: "http://othermyserver.com",
			WantValidSecret:     "secret",
			WantInvalidSecret:   "othersecret",
			WantRequiresPKCE:    false,
		},
		{
			Name:              "Missing client ID",
			ClientID:          "not-in-file",
			WantInvalidClient: true,
		},
		{
			Name:                "Public client with localhost redirect and PKCE",
			ClientID:            "publocalpkce",
			WantValidRedirect:   "http://localhost:8007/callback",
			WantInvalidRedirect: "http://othermyserver.com",
			WantValidSecret:     "", // empty secret should be fine
			WantRequiresPKCE:    true,
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
			Name:                "Env secret, with simple secrets secret and redirect",
			ClientID:            "envsecret",
			WantValidSecret:     "defaultsecret",
			WantInvalidSecret:   "secret", // valid for another client
			WantValidRedirect:   "http://envsecret.com",
			WantInvalidRedirect: "http://myserver.com",
		},
		{
			Name:              "Public client with localhost redirect and PKCE",
			ClientID:          "publocalpkceskip",
			WantInvalidSecret: "", // empty secret should not work
			WantRequiresPKCE:  false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			for k, v := range tc.WithEnv {
				os.Setenv(k, v)
				t.Cleanup(func() { os.Unsetenv(k) })
			}

			// after env set
			clients, err := ExpandUnmarshal(cb)
			if err != nil {
				t.Fatal(err)
			}

			valid, err := clients.IsValidClientID(tc.ClientID)
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

				if _, err := clients.RequiresPKCE(tc.ClientID); err == nil {
					t.Error("PKCE check should fail")
				}

				if _, err := clients.ValidateClientSecret(tc.ClientID, ""); err == nil {
					t.Error("client secret check should fail")
				}

				if _, err := clients.ValidateClientRedirectURI(tc.ClientID, ""); err == nil {
					t.Error("client redirect uri check should fail")
				}

				return
			}

			if !valid {
				t.Errorf("client %s should be valid", tc.ClientID)
			}

			requiresPKCE, err := clients.RequiresPKCE(tc.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.WantRequiresPKCE != requiresPKCE {
				t.Errorf("want requires PKCE %t, got: %t", tc.WantRequiresPKCE, requiresPKCE)
			}

			if tc.WantValidSecret != "" {
				valid, err := clients.ValidateClientSecret(tc.ClientID, tc.WantValidSecret)
				if err != nil {
					t.Fatal(err)
				}
				if !valid {
					t.Errorf("want secret %s to be valid, but it was not", tc.WantValidSecret)
				}
			}
			if tc.WantInvalidSecret != "" {
				valid, err := clients.ValidateClientSecret(tc.ClientID, tc.WantInvalidRedirect)
				if err != nil {
					t.Fatal(err)
				}
				if valid {
					t.Errorf("want secret %s to be invalid, but it was", tc.WantInvalidSecret)
				}
			}

			if tc.WantValidRedirect != "" {
				valid, err := clients.ValidateClientRedirectURI(tc.ClientID, tc.WantValidRedirect)
				if err != nil {
					t.Fatal(err)
				}
				if !valid {
					t.Errorf("want redirect %s to be valid, but it was not", tc.WantValidRedirect)
				}
			}
			if tc.WantInvalidRedirect != "" {
				valid, err := clients.ValidateClientRedirectURI(tc.ClientID, tc.WantInvalidRedirect)
				if err != nil {
					t.Fatal(err)
				}
				if valid {
					t.Errorf("want redirect %s to be invalid, but it was", tc.WantInvalidRedirect)
				}
			}

		})
	}
}
