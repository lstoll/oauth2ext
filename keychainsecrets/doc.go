// Package keychainsecrets provides a macOS keychain implementation of
// tokencache.Store. Credentials are cached in the keychain, and each login gets
// its own Secure Enclave DPoP key (P-256, or ML-DSA-65 or ML-DSA-87 where
// preferred and supported), whose device-bound blob is stored in the keychain
// entry alongside the token.
//
// NOTE: This package is currently experimental and may change significantly.
package keychainsecrets
