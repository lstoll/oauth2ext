// Package tpmsecrets provides a TPM-backed implementation of tokencache.Store.
//
// TPMCredentialCache stores credentials in a single file, encrypted with
// AES-256-GCM under a data key that is sealed by the TPM. Writes are atomic
// and serialized with a lock file.
//
// Each cached login gets its own DPoP key: NewDPoPKey creates a non-exportable
// P-256 key under the TPM's storage root key, and the key's wrapped blob (only
// loadable on the same TPM) is the handle that is stored in the cache next to
// the token. Nothing is stored for keys whose handles are discarded. Keys are
// not bound to the identity of the calling binary.
//
// NOTE: This package is currently experimental and may change significantly.
package tpmsecrets
