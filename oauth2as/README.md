# oidcop

Go library for implementing OIDC OPs (Servers)

## Example OP

An example server is provided. Can be run:

```
go run ./cmd/oidc-example-op
```

And interacted with via

```
go run github.com/lstoll/oidc/cmd/oidccli -issuer=http://localhost:8085 -client-id=cli -scopes=openid,offline_access -skip-cache info
```
