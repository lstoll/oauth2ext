package jwt

type Provider interface {
	Issuer() string
	Keyset() PublicKeyset
	SupportedAlgs() []string
}
