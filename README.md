# oauth2ext

[![Go Reference](https://pkg.go.dev/badge/lds.li/oauth2ext.svg)](https://pkg.go.dev/lds.li/oauth2ext)

Module that provides extensions for to the [x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) package, including OpenID connect (OIDC) usage.

* [**provider**](https://pkg.go.dev/lds.li/oauth2ext/oidc) Provides the ability to discover information from an OIDC/OAuth2 issuer, and handle tokens that contain OIDC ID Tokens
* [**clitoken**](https://pkg.go.dev/lds.li/oauth2ext/clitoken) Implements the three-legged OIDC flow for local/CLI applications, with a dynamic server on the loopback to handle the callback
* [**oidcmiddleware**](https://pkg.go.dev/lds.li/oauth2ext/oidcmiddleware) Provides a HTTP middleware to secure a path against an OIDC issuer
* [**tokencache**](https://pkg.go.dev/lds.li/oauth2ext/tokencache) Provides a mechanism for caching and refreshing tokens.

Examples:
* **cmd/oidc-example-rp** An example of a webapp that authenticates via OIDC
* (**oidcli**)[https://github.com/lstoll/oidccli] A CLI tool that uses the [clitoken](https://pkg.go.dev/lds.li/oauth2ext/clitoken) package to retrieve ID/Access tokens, and return them or information about them.
