package oauth2as

// JWTSigningInput is the server-selected JOSE type and typed claims. It is an
// internal staging value; jwt.Signer performs the JSON encoding and signing.
type JWTSigningInput struct {
	Type   string
	Claims map[string]any
}
