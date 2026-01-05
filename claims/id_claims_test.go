package claims

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/internal/th"
	"lds.li/oauth2ext/provider"
)

func TestIDClaims(t *testing.T) {
	rawOpts := &RawIDOptions{
		Issuer:    th.Ptr("https://example.com"),
		ClientID:  th.Ptr("https://example.com"),
		Subject:   th.Ptr("https://example.com"),
		IssuedAt:  th.Ptr(time.Now()),
		ExpiresAt: th.Ptr(time.Now().Add(1 * time.Hour)),
		NotBefore: th.Ptr(time.Now()),
		AMR:       []string{"amr1", "amr2"},
	}

	rOps, err := rawOpts.JWTOptions()
	if err != nil {
		t.Fatal(err)
	}

	_, err = jwt.NewRawJWT(rOps)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(rOps)
}

func TestIDTokenValidator(t *testing.T) {
	svr, testSigner := newMockDiscoveryServer()
	t.Cleanup(svr.Close)
	issuer := svr.URL
	clientID := "test-client-id"

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, svr.Client())
	p, err := provider.DiscoverOIDCProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("failed to discover provider: %v", err)
	}

	verifier, err := NewVerifier[*VerifiedID](p)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	createIDToken := func(iss, aud string, acr *string, customClaims map[string]any) *oauth2.Token {
		now := time.Now()
		opts := &jwt.RawJWTOptions{
			Issuer:    &iss,
			Audience:  &aud,
			Subject:   th.Ptr("test-subject"),
			IssuedAt:  &now,
			ExpiresAt: th.Ptr(now.Add(time.Hour)),
		}
		if opts.CustomClaims == nil {
			opts.CustomClaims = make(map[string]any)
		}
		if acr != nil {
			opts.CustomClaims["acr"] = *acr
		}
		maps.Copy(opts.CustomClaims, customClaims)

		rawJWT, err := jwt.NewRawJWT(opts)
		if err != nil {
			t.Fatalf("failed to create raw JWT: %v", err)
		}

		signed, err := testSigner.Sign(rawJWT)
		if err != nil {
			t.Fatalf("failed to sign JWT: %v", err)
		}

		return (&oauth2.Token{}).WithExtra(map[string]any{
			"id_token": signed,
		})
	}

	tests := []struct {
		name    string
		opts    *IDTokenValidatorOpts
		token   func() *oauth2.Token
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid token with matching client ID",
			opts: &IDTokenValidatorOpts{
				ClientID: &clientID,
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, clientID, nil, nil)
			},
			wantErr: false,
		},
		{
			name: "valid token with matching client ID and ACR",
			opts: &IDTokenValidatorOpts{
				ClientID:  &clientID,
				ACRValues: []string{"urn:mace:incommon:iap:silver"},
			},
			token: func() *oauth2.Token {
				acr := "urn:mace:incommon:iap:silver"
				return createIDToken(issuer, clientID, &acr, nil)
			},
			wantErr: false,
		},
		{
			name: "valid token with ACR in allowed list",
			opts: &IDTokenValidatorOpts{
				ClientID:  &clientID,
				ACRValues: []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:gold"},
			},
			token: func() *oauth2.Token {
				acr := "urn:mace:incommon:iap:gold"
				return createIDToken(issuer, clientID, &acr, nil)
			},
			wantErr: false,
		},
		{
			name: "valid token with IgnoreClientID",
			opts: &IDTokenValidatorOpts{
				IgnoreClientID: true,
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, "different-client-id", nil, nil)
			},
			wantErr: false,
		},
		{
			name: "invalid token with wrong issuer",
			opts: &IDTokenValidatorOpts{
				ClientID: &clientID,
			},
			token: func() *oauth2.Token {
				return createIDToken("https://wrong-issuer.com", clientID, nil, nil)
			},
			wantErr: true,
			errMsg:  "validating issuer claim",
		},
		{
			name: "invalid token with wrong audience",
			opts: &IDTokenValidatorOpts{
				ClientID: &clientID,
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, "wrong-client-id", nil, nil)
			},
			wantErr: true,
			errMsg:  "audience",
		},
		{
			name: "invalid token with missing ACR when required",
			opts: &IDTokenValidatorOpts{
				ClientID:  &clientID,
				ACRValues: []string{"urn:mace:incommon:iap:silver"},
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, clientID, nil, nil)
			},
			wantErr: true,
			errMsg:  "ACR claim found",
		},
		{
			name: "invalid token with wrong ACR value",
			opts: &IDTokenValidatorOpts{
				ClientID:  &clientID,
				ACRValues: []string{"urn:mace:incommon:iap:silver"},
			},
			token: func() *oauth2.Token {
				acr := "urn:mace:incommon:iap:bronze"
				return createIDToken(issuer, clientID, &acr, nil)
			},
			wantErr: true,
			errMsg:  "not in requested list",
		},
		{
			name: "invalid token with ACR as non-string",
			opts: &IDTokenValidatorOpts{
				ClientID:  &clientID,
				ACRValues: []string{"urn:mace:incommon:iap:silver"},
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, clientID, nil, map[string]any{
					"acr": 123, // ACR should be a string
				})
			},
			wantErr: true,
			errMsg:  "ACR claim found",
		},
		{
			name: "valid token with no opts and IgnoreClientID",
			opts: &IDTokenValidatorOpts{
				IgnoreClientID: true,
			},
			token: func() *oauth2.Token {
				return createIDToken(issuer, clientID, nil, nil)
			},
			wantErr: false,
		},
		{
			name: "invalid token missing id_token in extra",
			opts: &IDTokenValidatorOpts{
				ClientID: &clientID,
			},
			token: func() *oauth2.Token {
				return (&oauth2.Token{}).WithExtra(map[string]any{})
			},
			wantErr: true,
			errMsg:  "no id_token found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewIDTokenValidator(tt.opts)

			token := tt.token()
			verified, err := verifier.VerifyAndDecodeToken(t.Context(), *token, validator)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error message should contain %q, got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if verified == nil {
					t.Errorf("expected verified JWT but got nil")
				}
			}
		})
	}
}
