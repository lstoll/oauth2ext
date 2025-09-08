package oidcclientreg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"lds.li/oauth2ext/internal"
	"lds.li/oauth2ext/oidc"
)

func RegisterWithProvider(ctx context.Context, provider *oidc.Provider, request *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	if provider.Metadata.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("registration endpoint not found in provider metadata")
	}

	httpClient := internal.HTTPClientFromContext(ctx, nil)

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Metadata.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body to handle both success and error cases
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusBadRequest {
		// OIDC spec: registration errors return HTTP 400 with JSON error object
		var clientRegErr ClientRegistrationError
		if jsonErr := json.Unmarshal(respBody, &clientRegErr); jsonErr == nil && clientRegErr.ErrorCode != "" {
			// Successfully parsed as a ClientRegistrationError
			return nil, &clientRegErr
		}
	}

	// For other non-success status codes, return regular HTTP errors
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed with HTTP status %d: %s", resp.StatusCode, string(respBody))
	}

	var response ClientRegistrationResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	return &response, nil
}
