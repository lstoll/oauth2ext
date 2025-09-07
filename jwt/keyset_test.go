package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestPublicKey_Valid(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024) // do not use 1024 outside of tests!
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P256 key: %v", err)
	}

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P384 key: %v", err)
	}

	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P521 key: %v", err)
	}

	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name    string
		key     crypto.PublicKey
		alg     SigningAlg
		wantErr bool
		errMsg  string
	}{
		// Valid RSA cases
		{
			name:    "valid RSA with RS256",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgRS256,
			wantErr: false,
		},
		{
			name:    "valid RSA with RS384",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgRS384,
			wantErr: false,
		},
		{
			name:    "valid RSA with RS512",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgRS512,
			wantErr: false,
		},
		{
			name:    "valid RSA with PS256",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgPS256,
			wantErr: false,
		},
		{
			name:    "valid RSA with PS384",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgPS384,
			wantErr: false,
		},
		{
			name:    "valid RSA with PS512",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgPS512,
			wantErr: false,
		},

		// Valid ECDSA cases
		{
			name:    "valid P256 with ES256",
			key:     &p256Key.PublicKey,
			alg:     SigningAlgES256,
			wantErr: false,
		},
		{
			name:    "valid P384 with ES384",
			key:     &p384Key.PublicKey,
			alg:     SigningAlgES384,
			wantErr: false,
		},
		{
			name:    "valid P521 with ES512",
			key:     &p521Key.PublicKey,
			alg:     SigningAlgES512,
			wantErr: false,
		},

		// Valid Ed25519 cases
		{
			name:    "valid Ed25519 with EdDSA",
			key:     ed25519Pub,
			alg:     SigningAlgEdDSA,
			wantErr: false,
		},

		// Invalid RSA cases - wrong algorithm
		{
			name:    "RSA with ES256",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgES256,
			wantErr: true,
			errMsg:  "key algorithm is ES256, expected a RS/PS variant",
		},
		{
			name:    "RSA with EdDSA",
			key:     &rsaKey.PublicKey,
			alg:     SigningAlgEdDSA,
			wantErr: true,
			errMsg:  "key algorithm is EdDSA, expected a RS/PS variant",
		},

		// Invalid ECDSA cases - wrong algorithm
		{
			name:    "P256 with RS256",
			key:     &p256Key.PublicKey,
			alg:     SigningAlgRS256,
			wantErr: true,
			errMsg:  "key algorithm is RS256, expected ES256",
		},
		{
			name:    "P256 with ES384",
			key:     &p256Key.PublicKey,
			alg:     SigningAlgES384,
			wantErr: true,
			errMsg:  "key algorithm is ES384, expected ES256",
		},
		{
			name:    "P256 with ES512",
			key:     &p256Key.PublicKey,
			alg:     SigningAlgES512,
			wantErr: true,
			errMsg:  "key algorithm is ES512, expected ES256",
		},
		{
			name:    "P384 with ES256",
			key:     &p384Key.PublicKey,
			alg:     SigningAlgES256,
			wantErr: true,
			errMsg:  "key algorithm is ES256, expected ES384",
		},
		{
			name:    "P384 with ES512",
			key:     &p384Key.PublicKey,
			alg:     SigningAlgES512,
			wantErr: true,
			errMsg:  "key algorithm is ES512, expected ES384",
		},
		{
			name:    "P521 with ES256",
			key:     &p521Key.PublicKey,
			alg:     SigningAlgES256,
			wantErr: true,
			errMsg:  "key algorithm is ES256, expected ES512",
		},
		{
			name:    "P521 with ES384",
			key:     &p521Key.PublicKey,
			alg:     SigningAlgES384,
			wantErr: true,
			errMsg:  "key algorithm is ES384, expected ES512",
		},

		// Invalid Ed25519 cases - wrong algorithm
		{
			name:    "Ed25519 with ES256",
			key:     ed25519Pub,
			alg:     SigningAlgES256,
			wantErr: true,
			errMsg:  "key algorithm is ES256, expected EdDSA",
		},
		{
			name:    "Ed25519 with RS256",
			key:     ed25519Pub,
			alg:     SigningAlgRS256,
			wantErr: true,
			errMsg:  "key algorithm is RS256, expected EdDSA",
		},

		// Edge cases
		{
			name:    "nil key",
			key:     nil,
			alg:     SigningAlgRS256,
			wantErr: true,
			errMsg:  "key is nil",
		},
		{
			name:    "unsupported key type",
			key:     "not a key",
			alg:     SigningAlgRS256,
			wantErr: true,
			errMsg:  "unsupported key type: string",
		},
		{
			name: "unsupported curve",
			key: func() crypto.PublicKey {
				// Create an ECDSA key with an unsupported curve (P224)
				key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate unsupported curve key: %v", err)
				}
				return &key.PublicKey
			}(),
			alg:     SigningAlgES256,
			wantErr: true,
			errMsg:  "unsupported curve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := &PublicKey{
				KeyID: "test-key-id",
				Alg:   tt.alg,
				Key:   tt.key,
			}

			err := pk.Valid()
			if tt.wantErr {
				if err == nil {
					t.Errorf("PublicKey.Valid() expected error but got none")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("PublicKey.Valid() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("PublicKey.Valid() unexpected error = %v", err)
				}
			}
		})
	}
}
