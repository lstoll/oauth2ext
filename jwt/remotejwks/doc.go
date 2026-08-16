// Package remotejwks fetches and caches a JWKS from an HTTP URL.
//
// [Source] represents one jwks_uri. Callers that map identifiers to URLs,
// such as OAuth clients authenticating with private_key_jwt, should retain one
// Source per URL. Host allowlists and other SSRF controls are the caller's
// responsibility.
package remotejwks
