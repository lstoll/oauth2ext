package jwt

type Provider interface {
	GetIssuer() string
	GetKeyset() PublicKeyset
	GetSupportedAlgs() []string
}
