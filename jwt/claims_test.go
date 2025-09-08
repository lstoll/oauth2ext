package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"lds.li/oauth2ext/internal/th"
)

func TestClaimsJSONRoundtrip(t *testing.T) {
	tests := []struct {
		name        string
		claims      any
		expectError bool
		errorMsg    string
	}{
		{
			name: "IDClaims basic roundtrip",
			claims: &IDClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"client1"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				Extra: map[string]any{
					"custom_claim": "custom_value",
					"nested": map[string]any{
						"key": "value",
					},
				},
			},
		},
		{
			name: "IDClaims with multiple audiences",
			claims: &IDClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"client1", "client2"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				Nonce:    "nonce123",
				ACR:      "urn:mace:incommon:iap:silver",
				AMR:      []string{"pwd", "otp"},
				AZP:      "client1",
				Extra: map[string]any{
					"preferred_username": "johndoe",
					"email":              "john@example.com",
				},
			},
		},
		{
			name: "AccessTokenClaims basic roundtrip",
			claims: &AccessTokenClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"api.example.com"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				ClientID: "client1",
				JWTID:    "jwt123",
				Scope:    "read write",
				Extra: map[string]any{
					"custom_claim": "custom_value",
				},
			},
		},
		{
			name: "AccessTokenClaims with groups and roles",
			claims: &AccessTokenClaims{
				Issuer:       "https://example.com",
				Subject:      "user123",
				Audience:     StrOrSlice([]string{"api.example.com"}),
				Expiry:       UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt:     UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				ClientID:     "client1",
				JWTID:        "jwt123",
				Groups:       []string{"admin", "users"},
				Roles:        []string{"read", "write"},
				Entitlements: []string{"feature1", "feature2"},
				Extra: map[string]any{
					"preferred_username": "johndoe",
				},
			},
		},
		{
			name: "IDClaims with iss conflict in extra",
			claims: &IDClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"client1"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				Extra: map[string]any{
					"iss": "conflicting_issuer",
				},
			},
			expectError: true,
			errorMsg:    "json: error calling MarshalJSON for type *jwt.IDClaims: extra claim \"iss\" conflicts with standard claim",
		},
		{
			name: "IDClaims with sub conflict in extra",
			claims: &IDClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"client1"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				Extra: map[string]any{
					"sub": "conflicting_subject",
				},
			},
			expectError: true,
			errorMsg:    "json: error calling MarshalJSON for type *jwt.IDClaims: extra claim \"sub\" conflicts with standard claim",
		},
		{
			name: "AccessTokenClaims with client_id conflict in extra",
			claims: &AccessTokenClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"api.example.com"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				ClientID: "client1",
				JWTID:    "jwt123",
				Extra: map[string]any{
					"client_id": "conflicting_client_id",
				},
			},
			expectError: true,
			errorMsg:    "json: error calling MarshalJSON for type *jwt.AccessTokenClaims: extra claim \"client_id\" conflicts with standard claim",
		},
		{
			name: "AccessTokenClaims with jti conflict in extra",
			claims: &AccessTokenClaims{
				Issuer:   "https://example.com",
				Subject:  "user123",
				Audience: StrOrSlice([]string{"api.example.com"}),
				Expiry:   UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-20")).Unix()),
				IssuedAt: UnixTime(th.Must(time.Parse("2006-Jan-02", "2019-Nov-19")).Unix()),
				ClientID: "client1",
				JWTID:    "jwt123",
				Extra: map[string]any{
					"jti": "conflicting_jti",
				},
			},
			expectError: true,
			errorMsg:    "json: error calling MarshalJSON for type *jwt.AccessTokenClaims: extra claim \"jti\" conflicts with standard claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal the claims to JSON
			jsonData, err := json.Marshal(tt.claims)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to marshal claims: %v", err)
			}

			// Unmarshal back to a new instance
			var unmarshaledClaims any
			switch tt.claims.(type) {
			case *IDClaims:
				unmarshaledClaims = &IDClaims{}
			case *AccessTokenClaims:
				unmarshaledClaims = &AccessTokenClaims{}
			default:
				t.Fatal("unknown claims type")
			}

			if err := json.Unmarshal(jsonData, unmarshaledClaims); err != nil {
				t.Fatalf("failed to unmarshal claims: %v", err)
			}

			// Compare the original and unmarshaled claims
			if diff := cmp.Diff(tt.claims, unmarshaledClaims, cmpopts.IgnoreUnexported(IDClaims{}, AccessTokenClaims{})); diff != "" {
				t.Errorf("claims roundtrip failed (-want +got):\n%s", diff)
			}

			// Test UnmarshalClaims method if raw data is available
			switch claims := tt.claims.(type) {
			case *IDClaims:
				if len(claims.raw) > 0 {
					var dest map[string]any
					if err := claims.UnmarshalClaims(&dest); err != nil {
						t.Errorf("UnmarshalClaims failed: %v", err)
					}
				}
			case *AccessTokenClaims:
				if len(claims.raw) > 0 {
					var dest map[string]any
					if err := claims.UnmarshalClaims(&dest); err != nil {
						t.Errorf("UnmarshalClaims failed: %v", err)
					}
				}
			}
		})
	}
}

func TestClaimsUnmarshalClaimsError(t *testing.T) {
	// Test UnmarshalClaims with claims that don't have raw data
	idClaims := &IDClaims{
		Issuer:  "https://example.com",
		Subject: "user123",
	}

	var dest map[string]any
	err := idClaims.UnmarshalClaims(&dest)
	if err == nil {
		t.Fatal("expected error when calling UnmarshalClaims on claims without raw data")
	}
	if err.Error() != "can only unmarshal claims from a JSON created IDClaims" {
		t.Errorf("expected specific error message, got: %v", err)
	}

	accessClaims := &AccessTokenClaims{
		Issuer:  "https://example.com",
		Subject: "user123",
	}

	err = accessClaims.UnmarshalClaims(&dest)
	if err == nil {
		t.Fatal("expected error when calling UnmarshalClaims on claims without raw data")
	}
	if err.Error() != "can only unmarshal claims from a JSON created AccessTokenClaims" {
		t.Errorf("expected specific error message, got: %v", err)
	}
}

func TestClaimsJSONParsing(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		claimsType  string
		expectError bool
	}{
		{
			name: "IDClaims from JSON with extra claims",
			jsonData: `{
				"iss": "https://example.com",
				"sub": "user123",
				"aud": "client1",
				"exp": 1574208000,
				"iat": 1574121600,
				"custom_claim": "custom_value",
				"nested_claim": {"key": "value"}
			}`,
			claimsType: "IDClaims",
		},
		{
			name: "AccessTokenClaims from JSON with extra claims",
			jsonData: `{
				"iss": "https://example.com",
				"sub": "user123",
				"aud": "api.example.com",
				"exp": 1574208000,
				"iat": 1574121600,
				"client_id": "client1",
				"jti": "jwt123",
				"groups": ["admin", "users"],
				"roles": ["read", "write"],
				"custom_claim": "custom_value"
			}`,
			claimsType: "AccessTokenClaims",
		},
		{
			name: "IDClaims with single audience string",
			jsonData: `{
				"iss": "https://example.com",
				"sub": "user123",
				"aud": "client1",
				"exp": 1574208000,
				"iat": 1574121600
			}`,
			claimsType: "IDClaims",
		},
		{
			name: "IDClaims with multiple audiences array",
			jsonData: `{
				"iss": "https://example.com",
				"sub": "user123",
				"aud": ["client1", "client2"],
				"exp": 1574208000,
				"iat": 1574121600
			}`,
			claimsType: "IDClaims",
		},
		{
			name: "Invalid JSON",
			jsonData: `{
				"iss": "https://example.com",
				"sub": "user123",
				"aud": "client1",
				"exp": 1574208000,
				"iat": 1574121600,
			}`,
			claimsType:  "IDClaims",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims any
			switch tt.claimsType {
			case "IDClaims":
				claims = &IDClaims{}
			case "AccessTokenClaims":
				claims = &AccessTokenClaims{}
			default:
				t.Fatal("unknown claims type")
			}

			err := json.Unmarshal([]byte(tt.jsonData), claims)
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to unmarshal JSON: %v", err)
			}

			// Verify that extra claims were properly parsed
			switch c := claims.(type) {
			case *IDClaims:
				if c.Extra == nil {
					t.Error("expected Extra map to be populated")
				}
			case *AccessTokenClaims:
				if c.Extra == nil {
					t.Error("expected Extra map to be populated")
				}
			}
		})
	}
}
