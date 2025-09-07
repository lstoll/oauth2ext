package jwt

// Issuer returns information about the issuer for tokens we want to verify
// against.
type Issuer interface {
	// GetIssuerURL returns the URL of the issuer, which will correspond to the
	// `iss` claim.
	GetIssuerURL() string
	// GetKeyset returns the keyset for the issuer, which will be used to verify
	// the tokens.
	GetKeyset() PublicKeyset
	// GetSupportedAlgs returns the list of JWT algorithms supported by this
	// issuer.
	GetSupportedAlgs() []string
}

// StaticIssuer is a minimal implementation of the [Issuer] interface, to use
// with fixed values. Most cases will discovery an OIDC or OAuth2 provider.
type StaticIssuer struct {
	IssuerURL     string
	Keyset        PublicKeyset
	SupportedAlgs []string
}

func (b *StaticIssuer) GetIssuerURL() string {
	return b.IssuerURL
}

func (b *StaticIssuer) GetKeyset() PublicKeyset {
	return b.Keyset
}

func (b *StaticIssuer) GetSupportedAlgs() []string {
	return b.SupportedAlgs
}
