package dpop

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
)

// OAuth2Context returns a copy of ctx whose oauth2.HTTPClient adds DPoP proofs
// signed by signer to every request. Any client already in ctx is wrapped, so
// its transport and settings are kept. Use it for token endpoint requests,
// such as code exchanges and refreshes, that must be bound to signer.
func OAuth2Context(ctx context.Context, signer *jwt.SigningIdentity) context.Context {
	client := http.Client{}
	if existing, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && existing != nil {
		client = *existing
	}
	client.Transport = &Transport{Signer: signer, Base: client.Transport}
	return context.WithValue(ctx, oauth2.HTTPClient, &client)
}
