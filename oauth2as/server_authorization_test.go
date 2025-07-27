package oauth2as

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lstoll/oauth2as/internal/staticclients"
)

func TestParseAuthRequest(t *testing.T) {
	// Create a test server with static clients
	server := &Server{
		config: Config{
			Clients: &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           "test-client",
						Secrets:      []string{"test-secret"},
						RedirectURLs: []string{"https://client.example.com/callback", "https://client.example.com/callback2"},
					},
					{
						ID:           "single-redirect-client",
						Secrets:      []string{"single-secret"},
						RedirectURLs: []string{"https://single.example.com/callback"},
					},
					{
						ID:           "public-client",
						Secrets:      []string{},
						Public:       true,
						RedirectURLs: []string{"https://public.example.com/callback"},
					},
				},
			},
		},
		now: time.Now,
	}

	testCases := []struct {
		name        string
		queryParams string
		expectError bool
		errorMsg    string
		expected    *AuthRequest
	}{
		{
			name:        "Valid auth request with all parameters",
			queryParams: "response_type=code&client_id=test-client&redirect_uri=https://client.example.com/callback&state=test-state&scope=openid%20profile&code_challenge=test-challenge&code_challenge_method=S256&acr_values=1%202",
			expectError: false,
			expected: &AuthRequest{
				ClientID:      "test-client",
				RedirectURI:   "https://client.example.com/callback",
				State:         "test-state",
				Scopes:        []string{"openid", "profile"},
				CodeChallenge: "test-challenge",
				ACRValues:     []string{"1", "2"},
			},
		},
		{
			name:        "Valid auth request without redirect_uri (single redirect client)",
			queryParams: "response_type=code&client_id=single-redirect-client&state=test-state&scope=openid",
			expectError: false,
			expected: &AuthRequest{
				ClientID:    "single-redirect-client",
				RedirectURI: "https://single.example.com/callback",
				State:       "test-state",
				Scopes:      []string{"openid"},
			},
		},
		{
			name:        "Valid auth request with PKCE",
			queryParams: "response_type=code&client_id=test-client&redirect_uri=https://client.example.com/callback&state=test-state&code_challenge=abc123&code_challenge_method=S256",
			expectError: false,
			expected: &AuthRequest{
				ClientID:      "test-client",
				RedirectURI:   "https://client.example.com/callback",
				State:         "test-state",
				Scopes:        []string{""},
				CodeChallenge: "abc123",
			},
		},
		{
			name:        "Invalid client ID",
			queryParams: "response_type=code&client_id=invalid-client&redirect_uri=https://client.example.com/callback",
			expectError: true,
			errorMsg:    "client ID invalid-client is not valid",
		},
		{
			name:        "Invalid redirect URI",
			queryParams: "response_type=code&client_id=test-client&redirect_uri=https://attacker.example.com/callback",
			expectError: true,
			errorMsg:    "redirect URI https://attacker.example.com/callback is not valid for client ID test-client",
		},
		{
			name:        "Multiple redirect URIs but none provided",
			queryParams: "response_type=code&client_id=test-client",
			expectError: true,
			errorMsg:    "client ID test-client has multiple redirect URIs, but none were provided",
		},
		{
			name:        "Unsupported response type",
			queryParams: "response_type=token&client_id=test-client&redirect_uri=https://client.example.com/callback",
			expectError: true,
			errorMsg:    "response type token is not supported",
		},
		{
			name:        "Missing response_type",
			queryParams: "client_id=test-client&redirect_uri=https://client.example.com/callback",
			expectError: true,
			errorMsg:    "failed to parse auth request",
		},
		{
			name:        "Missing client_id",
			queryParams: "response_type=code&redirect_uri=https://client.example.com/callback",
			expectError: true,
			errorMsg:    "failed to parse auth request",
		},
		{
			name:        "Public client with valid redirect",
			queryParams: "response_type=code&client_id=public-client&redirect_uri=https://public.example.com/callback&state=test-state",
			expectError: false,
			expected: &AuthRequest{
				ClientID:    "public-client",
				RedirectURI: "https://public.example.com/callback",
				State:       "test-state",
				Scopes:      []string{""},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/auth?"+tc.queryParams, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			result, err := server.ParseAuthRequest(req)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("expected result but got nil")
				return
			}

			// Compare expected fields
			if tc.expected.ClientID != result.ClientID {
				t.Errorf("expected ClientID %s, got %s", tc.expected.ClientID, result.ClientID)
			}
			if tc.expected.RedirectURI != result.RedirectURI {
				t.Errorf("expected RedirectURI %s, got %s", tc.expected.RedirectURI, result.RedirectURI)
			}
			if tc.expected.State != result.State {
				t.Errorf("expected State %s, got %s", tc.expected.State, result.State)
			}
			if tc.expected.CodeChallenge != result.CodeChallenge {
				t.Errorf("expected CodeChallenge %s, got %s", tc.expected.CodeChallenge, result.CodeChallenge)
			}

			// Compare slices
			if len(tc.expected.Scopes) != len(result.Scopes) {
				t.Errorf("expected %d scopes, got %d", len(tc.expected.Scopes), len(result.Scopes))
			} else {
				for i, scope := range tc.expected.Scopes {
					if i >= len(result.Scopes) || scope != result.Scopes[i] {
						t.Errorf("expected scope[%d] %s, got %s", i, scope, result.Scopes[i])
					}
				}
			}

			if len(tc.expected.ACRValues) != len(result.ACRValues) {
				t.Errorf("expected %d ACR values, got %d", len(tc.expected.ACRValues), len(result.ACRValues))
			} else {
				for i, acr := range tc.expected.ACRValues {
					if i >= len(result.ACRValues) || acr != result.ACRValues[i] {
						t.Errorf("expected ACR[%d] %s, got %s", i, acr, result.ACRValues[i])
					}
				}
			}
		})
	}
}

func TestGrantAuth(t *testing.T) {
	// Create a test server with storage and clients
	storage := NewMemStorage()
	server := &Server{
		config: Config{
			Storage: storage,
			Clients: &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           "test-client",
						Secrets:      []string{"test-secret"},
						RedirectURLs: []string{"https://client.example.com/callback"},
					},
					{
						ID:           "multi-redirect-client",
						Secrets:      []string{"multi-secret"},
						RedirectURLs: []string{"https://client1.example.com/callback", "https://client2.example.com/callback"},
					},
				},
			},
			CodeValidityTime: 10 * time.Minute,
		},
		now: time.Now,
	}

	testCases := []struct {
		name        string
		authRequest *AuthRequest
		grant       *AuthGrant
		expectError bool
		errorMsg    string
		checkResult func(t *testing.T, redirectURI string)
	}{
		{
			name: "Valid grant with all scopes",
			authRequest: &AuthRequest{
				ClientID:    "test-client",
				RedirectURI: "https://client.example.com/callback",
				State:       "test-state",
				Scopes:      []string{"openid", "profile", "email"},
			},
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					State:       "test-state",
					Scopes:      []string{"openid", "profile", "email"},
				},
				GrantedScopes: []string{"openid", "profile", "email"},
				UserID:        "user123",
			},
			expectError: false,
			checkResult: func(t *testing.T, redirectURI string) {
				if !strings.Contains(redirectURI, "https://client.example.com/callback") {
					t.Errorf("expected redirect URI to contain https://client.example.com/callback, got %s", redirectURI)
				}
				if !strings.Contains(redirectURI, "state=test-state") {
					t.Errorf("expected redirect URI to contain state=test-state, got %s", redirectURI)
				}
				if !strings.Contains(redirectURI, "code=") {
					t.Errorf("expected redirect URI to contain code parameter, got %s", redirectURI)
				}
			},
		},
		{
			name: "Valid grant with partial scopes",
			authRequest: &AuthRequest{
				ClientID:    "test-client",
				RedirectURI: "https://client.example.com/callback",
				State:       "partial-state",
				Scopes:      []string{"openid", "profile", "email", "admin"},
			},
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					State:       "partial-state",
					Scopes:      []string{"openid", "profile", "email", "admin"},
				},
				GrantedScopes: []string{"openid", "profile"}, // Only grant some scopes
				UserID:        "user456",
			},
			expectError: false,
			checkResult: func(t *testing.T, redirectURI string) {
				if !strings.Contains(redirectURI, "state=partial-state") {
					t.Errorf("expected redirect URI to contain state=partial-state, got %s", redirectURI)
				}
			},
		},
		{
			name: "Valid grant with PKCE",
			authRequest: &AuthRequest{
				ClientID:      "test-client",
				RedirectURI:   "https://client.example.com/callback",
				State:         "pkce-state",
				Scopes:        []string{"openid"},
				CodeChallenge: "test-challenge",
			},
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:      "test-client",
					RedirectURI:   "https://client.example.com/callback",
					State:         "pkce-state",
					Scopes:        []string{"openid"},
					CodeChallenge: "test-challenge",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "user789",
			},
			expectError: false,
			checkResult: func(t *testing.T, redirectURI string) {
				if !strings.Contains(redirectURI, "state=pkce-state") {
					t.Errorf("expected redirect URI to contain state=pkce-state, got %s", redirectURI)
				}
			},
		},
		{
			name: "Missing user ID",
			authRequest: &AuthRequest{
				ClientID:    "test-client",
				RedirectURI: "https://client.example.com/callback",
				State:       "test-state",
			},
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					State:       "test-state",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "", // Missing user ID
			},
			expectError: true,
			errorMsg:    "user ID is required",
		},
		{
			name: "Missing auth request",
			grant: &AuthGrant{
				Request:       nil, // Missing request
				GrantedScopes: []string{"openid"},
				UserID:        "user123",
			},
			expectError: true,
			errorMsg:    "auth request is required",
		},
		{
			name: "Invalid redirect URI in grant",
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "test-client",
					RedirectURI: "https://attacker.example.com/callback", // Invalid redirect
					State:       "test-state",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "user123",
			},
			expectError: true,
			errorMsg:    "redirect URI https://attacker.example.com/callback is not valid for client ID test-client",
		},
		{
			name: "Multi-redirect client with valid URI",
			authRequest: &AuthRequest{
				ClientID:    "multi-redirect-client",
				RedirectURI: "https://client1.example.com/callback",
				State:       "multi-state",
			},
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "multi-redirect-client",
					RedirectURI: "https://client1.example.com/callback",
					State:       "multi-state",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "user-multi",
			},
			expectError: false,
			checkResult: func(t *testing.T, redirectURI string) {
				if !strings.Contains(redirectURI, "https://client1.example.com/callback") {
					t.Errorf("expected redirect URI to contain https://client1.example.com/callback, got %s", redirectURI)
				}
				if !strings.Contains(redirectURI, "state=multi-state") {
					t.Errorf("expected redirect URI to contain state=multi-state, got %s", redirectURI)
				}
			},
		},
		{
			name: "Single redirect client with no redirect URI in grant",
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "test-client",
					RedirectURI: "", // No redirect URI specified
					State:       "no-redirect-state",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "user-no-redirect",
			},
			expectError: false,
			checkResult: func(t *testing.T, redirectURI string) {
				if !strings.Contains(redirectURI, "https://client.example.com/callback") {
					t.Errorf("expected redirect URI to contain https://client.example.com/callback, got %s", redirectURI)
				}
				if !strings.Contains(redirectURI, "state=no-redirect-state") {
					t.Errorf("expected redirect URI to contain state=no-redirect-state, got %s", redirectURI)
				}
			},
		},
		{
			name: "Multi-redirect client with no redirect URI in grant",
			grant: &AuthGrant{
				Request: &AuthRequest{
					ClientID:    "multi-redirect-client",
					RedirectURI: "", // No redirect URI specified
					State:       "multi-no-redirect-state",
				},
				GrantedScopes: []string{"openid"},
				UserID:        "user-multi-no-redirect",
			},
			expectError: true,
			errorMsg:    "client ID multi-redirect-client has multiple redirect URIs, but none were provided",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set the auth request in the grant if not already set
			if tc.grant != nil && tc.authRequest != nil {
				tc.grant.Request = tc.authRequest
			}

			redirectURI, err := server.GrantAuth(context.Background(), tc.grant)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if redirectURI == "" {
				t.Error("expected redirect URI but got empty string")
				return
			}

			// Validate the redirect URI format
			parsed, err := url.Parse(redirectURI)
			if err != nil {
				t.Errorf("failed to parse redirect URI: %v", err)
				return
			}

			if parsed.Scheme == "" || parsed.Host == "" {
				t.Errorf("invalid redirect URI format: %s", redirectURI)
			}

			// Run custom checks if provided
			if tc.checkResult != nil {
				tc.checkResult(t, redirectURI)
			}

			// Verify that a grant was created in storage
			if tc.grant != nil && tc.grant.UserID != "" {
				// We can't easily verify the grant was stored without exposing internal methods,
				// but we can verify the redirect URI contains the expected components
				if !strings.Contains(redirectURI, "code=") {
					t.Error("expected redirect URI to contain authorization code")
				}
			}
		})
	}
}

func TestAuthRequestIntegration(t *testing.T) {
	// Test the full flow from parsing to granting
	storage := NewMemStorage()
	server := &Server{
		config: Config{
			Storage: storage,
			Clients: &staticclients.Clients{
				Clients: []staticclients.Client{
					{
						ID:           "integration-client",
						Secrets:      []string{"integration-secret"},
						RedirectURLs: []string{"https://integration.example.com/callback"},
					},
				},
			},
			CodeValidityTime: 10 * time.Minute,
		},
		now: time.Now,
	}

	// Step 1: Parse auth request
	queryParams := "response_type=code&client_id=integration-client&redirect_uri=https://integration.example.com/callback&state=integration-test&scope=openid%20profile&code_challenge=integration-challenge&code_challenge_method=S256"
	req, err := http.NewRequest("GET", "/auth?"+queryParams, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	authReq, err := server.ParseAuthRequest(req)
	if err != nil {
		t.Fatalf("failed to parse auth request: %v", err)
	}

	// Verify parsed request
	if authReq.ClientID != "integration-client" {
		t.Errorf("expected client ID integration-client, got %s", authReq.ClientID)
	}
	if authReq.RedirectURI != "https://integration.example.com/callback" {
		t.Errorf("expected redirect URI https://integration.example.com/callback, got %s", authReq.RedirectURI)
	}
	if authReq.State != "integration-test" {
		t.Errorf("expected state integration-test, got %s", authReq.State)
	}
	if len(authReq.Scopes) != 2 || authReq.Scopes[0] != "openid" || authReq.Scopes[1] != "profile" {
		t.Errorf("expected scopes [openid profile], got %v", authReq.Scopes)
	}
	if authReq.CodeChallenge != "integration-challenge" {
		t.Errorf("expected code challenge integration-challenge, got %s", authReq.CodeChallenge)
	}

	// Step 2: Grant auth
	grant := &AuthGrant{
		Request:       authReq,
		GrantedScopes: []string{"openid", "profile"},
		UserID:        "integration-user",
	}

	redirectURI, err := server.GrantAuth(context.Background(), grant)
	if err != nil {
		t.Fatalf("failed to grant auth: %v", err)
	}

	// Verify redirect URI
	if !strings.Contains(redirectURI, "https://integration.example.com/callback") {
		t.Errorf("expected redirect URI to contain https://integration.example.com/callback, got %s", redirectURI)
	}
	if !strings.Contains(redirectURI, "state=integration-test") {
		t.Errorf("expected redirect URI to contain state=integration-test, got %s", redirectURI)
	}
	if !strings.Contains(redirectURI, "code=") {
		t.Errorf("expected redirect URI to contain authorization code, got %s", redirectURI)
	}

	// Parse the redirect URI to verify structure
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("failed to parse redirect URI: %v", err)
	}

	// Verify query parameters
	query := parsed.Query()
	if query.Get("state") != "integration-test" {
		t.Errorf("expected state parameter to be integration-test, got %s", query.Get("state"))
	}
	if query.Get("code") == "" {
		t.Error("expected code parameter to be present")
	}
}
