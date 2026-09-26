# oauth2ext

[![Go Reference](https://pkg.go.dev/badge/lds.li/oauth2ext.svg)](https://pkg.go.dev/lds.li/oauth2ext)

Extensions to [x/oauth2](https://pkg.go.dev/golang.org/x/oauth2), including OpenID Connect (OIDC) discovery and token verification.

* [**provider**](https://pkg.go.dev/lds.li/oauth2ext/provider) Discovers OIDC providers and maintains their verification keys.
* [**claims**](https://pkg.go.dev/lds.li/oauth2ext/claims) Validates OIDC ID-token claims.
* [**clientjwt**](https://pkg.go.dev/lds.li/oauth2ext/clientjwt) Authenticates OAuth clients with private_key_jwt, including refresh requests.
* [**clitoken**](https://pkg.go.dev/lds.li/oauth2ext/clitoken) Runs authorization-code flows for local applications using a loopback callback.
* [**middleware**](https://pkg.go.dev/lds.li/oauth2ext/middleware) Protects HTTP handlers with OIDC sign-in.
* [**tokencache**](https://pkg.go.dev/lds.li/oauth2ext/tokencache) Caches and refreshes OAuth tokens.

Examples:
* **cmd/oidc-example-rp** An example of a webapp that authenticates via OIDC
* [**oidcli**](https://github.com/lstoll/oidccli) A CLI tool that uses the [clitoken](https://pkg.go.dev/lds.li/oauth2ext/clitoken) package to retrieve ID/Access tokens, and return them or information about them.
