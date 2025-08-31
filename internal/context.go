package internal

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// HTTPClientFromContext returns a *http.Client for use. It will first check the
// context for the oauth2.HTTPClient, then explicit if not nil, then falling
// back to the default client.
func HTTPClientFromContext(ctx context.Context, explicit *http.Client) *http.Client {
	hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if ok {
		return hc
	}
	if explicit != nil {
		return explicit
	}
	return http.DefaultClient
}
