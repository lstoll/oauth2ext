// Package clientjwt implements OIDC private_key_jwt client authentication
// (RFC 7523 client assertions).
//
// Clients mint a JWT for each token request. Authorization servers verify that
// JWT against the client's JWKS. This is client authentication, not the
// jwt-bearer grant type.
package clientjwt
