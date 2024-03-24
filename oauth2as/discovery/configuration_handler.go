package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lstoll/oidc"
	"github.com/tink-crypto/tink-go/v2/jwt"
)

const awsSTSUserAgent = "AWS Security Token Service"

const DefaultCacheFor = 1 * time.Minute

var _ http.Handler = (*ConfigurationHandler)(nil)

// ConfigurationHandler is a http.ConfigurationHandler that can serve the OIDC
// provider metadata endpoint, and keys from a source.
//
// It should be mounted at `<issuer>/.well-known/openid-configuration`, and all
// subpaths. This can be achieved with the stdlib mux by using a trailing slash.
// Any prefix should be stripped before calling this ConfigurationHandler
type ConfigurationHandler struct {
	md     *oidc.ProviderMetadata
	keyset oidc.PublicHandle

	mux *http.ServeMux

	cacheFor time.Duration

	currJWKS   []byte
	currJWKSMu sync.Mutex

	lastKeysUpdate time.Time
}

// DefaultCoreMetadata returns a ProviderMetadata instance with defaults
// suitable for the core package in this module. Most endpoints will need to be
// added to this.
func DefaultCoreMetadata(issuer string) *oidc.ProviderMetadata {
	return &oidc.ProviderMetadata{
		Issuer: issuer,
		ResponseTypesSupported: []string{
			"code",
			"id_token",
			"id_token token",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		GrantTypesSupported:              []string{"authorization_code"},
		CodeChallengeMethodsSupported:    []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		JWKSURI:                          issuer + "/.well-known/jwks.json",
	}
}

// NewConfigurationHandler configures and returns a ConfigurationHandler.
func NewConfigurationHandler(metadata *oidc.ProviderMetadata, keyset oidc.PublicHandle) (*ConfigurationHandler, error) {
	h := &ConfigurationHandler{
		md:       metadata,
		keyset:   keyset,
		mux:      http.NewServeMux(),
		cacheFor: DefaultCacheFor,
	}

	if err := validateMetadata(h.md); err != nil {
		return nil, err
	}

	if err := h.getJWKS(context.Background()); err != nil {
		return nil, fmt.Errorf("initial jwks get: %w", err)
	}

	h.mux.HandleFunc("GET /.well-known/openid-configuration", h.serveConfig)
	h.mux.HandleFunc("GET /.well-known/jwks.json", h.serveKeys)

	return h, nil
}

func (h *ConfigurationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *ConfigurationHandler) serveConfig(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(h.md); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

func (h *ConfigurationHandler) serveKeys(w http.ResponseWriter, req *http.Request) {
	if err := h.getJWKS(req.Context()); err != nil {
		slog.ErrorContext(req.Context(), "getting jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
	}
	jwks := h.currJWKS

	if strings.Contains(req.UserAgent(), awsSTSUserAgent) {
		// AWS STS rejects JWKS that contains a "key_ops" field with the value
		// of "verify" (other values not tested). This seems like a mistake and
		// are going to follow up with them, in the mean time make it happy by
		// removing the fields.
		j, err := stripKeyOps(jwks)
		if err != nil {
			slog.ErrorContext(req.Context(), "failed to write jwks", "err", err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		jwks = j
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	if _, err := w.Write(jwks); err != nil {
		slog.ErrorContext(req.Context(), "failed to write jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

// getJWKS reads the keyset from the handle, and stores it on this instance.
func (h *ConfigurationHandler) getJWKS(ctx context.Context) error {
	h.currJWKSMu.Lock()
	defer h.currJWKSMu.Unlock()

	if h.currJWKS == nil || time.Now().After(h.lastKeysUpdate.Add(h.cacheFor)) {
		ph, err := h.keyset.PublicHandle(ctx)
		if err != nil {
			return fmt.Errorf("getting public handle: %w", err)
		}
		publicJWKset, err := jwt.JWKSetFromPublicKeysetHandle(ph)
		if err != nil {
			return fmt.Errorf("creating jwks from handle: %w", err)
		}

		h.currJWKS = publicJWKset
		h.lastKeysUpdate = time.Now()
	}

	return nil
}

func validateMetadata(p *oidc.ProviderMetadata) error {
	var errs []string

	aestr := func(val, e string) {
		if val == "" {
			errs = append(errs, e)
		}
	}

	aessl := func(val []string, e string) {
		if len(val) == 0 {
			errs = append(errs, e)
		}
	}

	aestr(p.Issuer, "Issuer is required")
	aestr(p.AuthorizationEndpoint, "AuthorizationEndpoint is required")
	aestr(p.JWKSURI, "JWKSURI is required")
	aessl(p.ResponseTypesSupported, "ResponseTypes supported is required")
	aessl(p.SubjectTypesSupported, "Subject Identifier Types are required")
	aessl(p.IDTokenSigningAlgValuesSupported, "IDTokenSigningAlgValuesSupported are required")

	if p.TokenEndpoint == "" {
		if len(p.GrantTypesSupported) != 1 || p.GrantTypesSupported[0] != "implicit" {
			errs = append(errs, "TokenEndpoint is required when we're not implicit-only")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid provider metadata: %s", strings.Join(errs, ", "))
	}
	return nil
}

// stripKeyOps removes the key_ops field from the raw JWKS json.
func stripKeyOps(in []byte) ([]byte, error) {
	var jwks map[string]any
	if err := json.Unmarshal(in, &jwks); err != nil {
		return nil, fmt.Errorf("unmarshaling input jwks: %w", err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil, fmt.Errorf("jwks does not contain keys entry")
	}
	for _, k := range keys {
		km, ok := k.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("key entry is not a map")
		}
		delete(km, "key_ops")
	}
	return json.Marshal(jwks)
}
