package oidcclientreg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lstoll/oauth2ext/oidc"
	"golang.org/x/oauth2"
)

func TestRegisterWithProvider(t *testing.T) {
	tests := []struct {
		name           string
		request        *ClientRegistrationRequest
		serverResponse interface{}
		statusCode     int
		wantErr        bool
		wantErrorCode  string
	}{
		{
			name: "successful registration",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: ClientRegistrationResponse{
				ClientID:                "client123",
				ClientSecret:            "secret123",
				ClientIDIssuedAt:        1234567890,
				RegistrationAccessToken: "reg_token_123",
				RegistrationClientURI:   "https://provider.com/register/client123",
				RedirectURIs:            []string{"https://example.com/callback"},
			},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name: "invalid redirect URI error",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"invalid-uri"},
			},
			serverResponse: ClientRegistrationError{
				ErrorCode:        ErrorInvalidRedirectURI,
				ErrorDescription: "One or more redirect_uri values are invalid",
			},
			statusCode:    http.StatusBadRequest,
			wantErr:       true,
			wantErrorCode: ErrorInvalidRedirectURI,
		},
		{
			name: "invalid client metadata error",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				ClientName:   "", // Empty client name might be invalid
			},
			serverResponse: ClientRegistrationError{
				ErrorCode:        ErrorInvalidClientMetadata,
				ErrorDescription: "Client name is required",
			},
			statusCode:    http.StatusBadRequest,
			wantErr:       true,
			wantErrorCode: ErrorInvalidClientMetadata,
		},
		{
			name: "server error (non-400)",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			serverResponse: "Internal server error",
			statusCode:     http.StatusInternalServerError,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and content type
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
				}

				// Set response status
				w.WriteHeader(tt.statusCode)

				// Write response body
				if tt.serverResponse != nil {
					if err := json.NewEncoder(w).Encode(tt.serverResponse); err != nil {
						t.Errorf("failed to encode response: %v", err)
					}
				}
			}))
			defer server.Close()

			// Create provider with test server URL
			provider := &oidc.Provider{
				Metadata: &oidc.ProviderMetadata{
					RegistrationEndpoint: server.URL,
				},
			}

			// Create context with HTTP client that skips TLS verification for testing
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())

			// Call RegisterWithProvider
			response, err := RegisterWithProvider(ctx, provider, tt.request)

			// Check error expectations
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
					return
				}

				// Check if it's a ClientRegistrationError when expected
				if tt.wantErrorCode != "" {
					var clientRegErr *ClientRegistrationError
					if !errors.As(err, &clientRegErr) {
						t.Errorf("expected ClientRegistrationError, got %T: %v", err, err)
						return
					}
					if clientRegErr.ErrorCode != tt.wantErrorCode {
						t.Errorf("expected error code %s, got %s", tt.wantErrorCode, clientRegErr.ErrorCode)
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Errorf("expected response, got nil")
					return
				}
			}
		})
	}
}
