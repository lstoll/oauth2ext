package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
)

const DefaultCacheFor = 1 * time.Minute

var _ http.Handler = (*OIDCConfigurationHandler)(nil)

// OIDCConfigurationHandler is a http.ConfigurationHandler that can serve the
// OIDC provider metadata endpoint, and keys from a source.
//
// It should be mounted at `GET /.well-known/openid-configuration`, and `GET
// /.well-known/jwks.json` (unless overridden)
type OIDCConfigurationHandler struct {
	md         *oidc.ProviderMetadata
	jwksSource JWKSSource

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

// Keyset is an interface that can be implemented by a type to provide a set of
// public keys to serve as the provider's verification keyset.
type Keyset interface {
	// GetKeys returns the full set of valid public keys for this provider.
	GetKeys(ctx context.Context) ([]jwt.PublicKey, error)
}

type keysetJWKSSource struct {
	keyset Keyset
}

func (s *keysetJWKSSource) GetJWKS(ctx context.Context) ([]byte, error) {
	pks, err := s.keyset.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting public handle: %w", err)
	}

	var jwks jose.JSONWebKeySet
	for _, k := range pks {
		if err := k.Valid(); err != nil {
			return nil, fmt.Errorf("invalid key %s in keyset: %w", k.KeyID, err)
		}
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			KeyID:     k.KeyID,
			Algorithm: string(k.Alg),
			Key:       k.Key,
		})
	}

	publicJWKset, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("creating jwks from handle: %w", err)
	}
	return publicJWKset, nil
}

// JWKSSource can be used to return a JWKS to serve on the discovery endpoint.
// No verification will be done on the JWKS.
type JWKSSource interface {
	GetJWKS(context.Context) ([]byte, error)
}

// NewOIDCConfigurationHandlerWithKeyset is the same as
// NewConfigurationHandlerWithJWKSSource, but it takes a Keyset instead of a
// JWKSSource.
func NewOIDCConfigurationHandlerWithKeyset(metadata *oidc.ProviderMetadata, keyset Keyset) (*OIDCConfigurationHandler, error) {
	jwksSource := &keysetJWKSSource{keyset: keyset}
	return NewOIDCConfigurationHandlerWithJWKSSource(metadata, jwksSource)
}

// NewOIDCConfigurationHandlerWithJWKSSource configures and returns a
// ConfigurationHandler for the given provider metadata and keyset.
//
// The handler should be configured to serve the following paths:
// GET /.well-known/openid-configuration
// GET /.well-known/jwks.json (unless overridden)
func NewOIDCConfigurationHandlerWithJWKSSource(metadata *oidc.ProviderMetadata, jwksSource JWKSSource) (*OIDCConfigurationHandler, error) {
	h := &OIDCConfigurationHandler{
		md:         metadata,
		jwksSource: jwksSource,
		mux:        http.NewServeMux(),
		cacheFor:   DefaultCacheFor,
	}

	jwksPath := `/.well-known/jwks.json`
	if metadata.JWKSURI != "" {
		// Note - if it's a different host, this will fail. If that is a desired
		// use case, the metadata serving should be constructed manually.
		u, err := url.Parse(metadata.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("parsing JWKSURI %s: %w", metadata.JWKSURI, err)
		}
		jwksPath = u.Path
	} else {
		metadata.JWKSURI = metadata.Issuer + jwksPath
	}

	if err := validateMetadata(h.md); err != nil {
		return nil, err
	}

	if err := h.getJWKS(context.Background()); err != nil {
		return nil, fmt.Errorf("initial jwks get: %w", err)
	}

	h.mux.HandleFunc("GET /.well-known/openid-configuration", h.serveConfig)
	h.mux.HandleFunc("GET "+jwksPath, h.serveKeys)

	return h, nil
}

func (h *OIDCConfigurationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *OIDCConfigurationHandler) serveConfig(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(h.md); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

func (h *OIDCConfigurationHandler) serveKeys(w http.ResponseWriter, req *http.Request) {
	if err := h.getJWKS(req.Context()); err != nil {
		slog.ErrorContext(req.Context(), "getting jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
	}
	jwks := h.currJWKS

	w.Header().Set("Content-Type", "application/jwk-set+json")
	if _, err := w.Write(jwks); err != nil {
		slog.ErrorContext(req.Context(), "failed to write jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}

// getJWKS reads the keyset from the handle, and stores it on this instance.
func (h *OIDCConfigurationHandler) getJWKS(ctx context.Context) error {
	h.currJWKSMu.Lock()
	defer h.currJWKSMu.Unlock()

	if h.currJWKS == nil || time.Now().After(h.lastKeysUpdate.Add(h.cacheFor)) {
		jwks, err := h.jwksSource.GetJWKS(ctx)
		if err != nil {
			return fmt.Errorf("getting jwks: %w", err)
		}
		h.currJWKS = jwks

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
