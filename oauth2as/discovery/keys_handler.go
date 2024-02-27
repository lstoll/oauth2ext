package discovery

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

// KeySource is used to retrieve the public keys this provider is signing with
type KeySource interface {
	// PublicKeys should return the current signing key set handle, with public keys only
	PublicHandle(ctx context.Context) (*keyset.Handle, error)
}

// KeysHandler is a http.Handler that correctly serves the "keys" endpoint from a keysource
type KeysHandler struct {
	ks       KeySource
	cacheFor time.Duration

	currJWKS   []byte
	currJWKSMu sync.Mutex

	lastKeysUpdate time.Time
}

// NewKeysHandler returns a KeysHandler configured to serve the keys froom
// KeySource. It will cache key lookups for the cacheFor duration
func NewKeysHandler(s KeySource, cacheFor time.Duration) *KeysHandler {
	return &KeysHandler{
		ks:       s,
		cacheFor: cacheFor,
	}
}

func (h *KeysHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.currJWKSMu.Lock()
	defer h.currJWKSMu.Unlock()

	if h.currJWKS == nil || time.Now().After(h.lastKeysUpdate) {
		ph, err := h.ks.PublicHandle(req.Context())
		if err != nil {
			slog.ErrorContext(req.Context(), "failed to get public key handle", "err", err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		publicJWKset, err := jwt.JWKSetFromPublicKeysetHandle(ph)
		if err != nil {
			slog.ErrorContext(req.Context(), "failed to get public key handle", "err", err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}

		h.currJWKS = publicJWKset
		h.lastKeysUpdate = time.Now()
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	if _, err := w.Write(h.currJWKS); err != nil {
		slog.ErrorContext(req.Context(), "failed to write jwks", "err", err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
}
