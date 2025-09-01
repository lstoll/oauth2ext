package oidcclientreg

import (
	"time"
)

// ClientRegistrationRequest represents the client metadata sent during dynamic client registration.
// Based on OpenID Connect Dynamic Client Registration 1.0 specification.
type ClientRegistrationRequest struct {
	// RedirectURIs is REQUIRED. Array of Redirection URI values used by the Client.
	// One of these registered Redirection URI values MUST exactly match the redirect_uri parameter
	// value used in each Authorization Request, with the matching performed as described in
	// Section 6.2.1 of RFC3986 (Simple String Comparison).
	RedirectURIs []string `json:"redirect_uris"`

	// ResponseTypes is OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client
	// is declaring that it will restrict itself to using. If omitted, the default is that the
	// Client will use only the "code" Response Type.
	ResponseTypes []string `json:"response_types,omitempty"`

	// GrantTypes is OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is
	// declaring that it will restrict itself to using. If omitted, the default is that the Client
	// will use only the "authorization_code" Grant Type.
	GrantTypes []string `json:"grant_types,omitempty"`

	// ApplicationType is OPTIONAL. Kind of the application. The defined values are "native" or "web".
	// Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https
	// scheme as redirect_uris; they MUST NOT use localhost as the hostname.
	// Native Clients MUST only register redirect_uris using custom URI schemes or URLs using the
	// http scheme with localhost as the hostname.
	ApplicationType string `json:"application_type,omitempty"`

	// Contacts is OPTIONAL. Array of e-mail addresses of people responsible for this Client.
	// This might be used by some providers to enable a Web user interface to modify the Client
	// information.
	Contacts []string `json:"contacts,omitempty"`

	// ClientName is OPTIONAL. Name of the Client to be presented to the End-User.
	// If desired, representation of this name in multiple languages and scripts is provided
	// using the structure described in Section 2.1.
	ClientName string `json:"client_name,omitempty"`

	// LogoURI is OPTIONAL. URL that references a logo for the Client application. If present, the server
	// SHOULD display this image to the End-User during approval. The value of this field MUST
	// point to a valid image file. If desired, representation of this logo in multiple languages
	// and scripts is provided using the structure described in Section 2.1.
	LogoURI string `json:"logo_uri,omitempty"`

	// ClientURI is OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a
	// valid Web page. If desired, representation of this URL in multiple languages and scripts
	// is provided using the structure described in Section 2.1.
	ClientURI string `json:"client_uri,omitempty"`

	// PolicyURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// how the profile data will be used. The value of this field MUST point to a valid web page.
	// If desired, representation of this URL in multiple languages and scripts is provided using
	// the structure described in Section 2.1.
	PolicyURI string `json:"policy_uri,omitempty"`

	// TermsOfServiceURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// Relying Party's terms of service. The value of this field MUST point to a valid web page.
	// If desired, representation of this URL in multiple languages and scripts is provided using
	// the structure described in Section 2.1.
	TermsOfServiceURI string `json:"terms_of_service_uri,omitempty"`

	// JwksURI is OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs
	// requests to the Server, it contains the signing key(s) the Server uses to validate
	// signatures from the Client. The JWK Set MAY also contain the Client's encryption keys(s),
	// which are used by the Server to encrypt responses to the Client. When both signing and
	// encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all
	// keys in the referenced JWK Set to indicate each key's intended usage.
	JwksURI string `json:"jwks_uri,omitempty"`

	// Jwks is OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the
	// jwks parameter are the same as the jwks_uri parameter, other than the JWK Set is passed
	// by value, rather than by reference. This parameter is intended only to be used by Clients
	// that, for some reason, cannot use the jwks_uri parameter, for instance, by native
	// applications that might not have a location to host the contents of the JWK Set. If a
	// Client can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that
	// it does not enable key rotation (which jwks_uri does, as described in Section 10 of
	// OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri and jwks parameters MUST NOT be
	// used together.
	Jwks interface{} `json:"jwks,omitempty"`

	// SectorIdentifierURI is OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers
	// by the OP. The URL references a file with a single JSON array of redirect_uri values.
	// Please see Section 5. of the OpenID Connect Core 1.0 [OpenID.Core] for more details.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// SubjectType is OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported
	// Discovery parameter contains a list of the supported subject_type values for this server.
	// Valid types include "pairwise" and "public".
	SubjectType string `json:"subject_type,omitempty"`

	// IdTokenSignedResponseAlg is OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client.
	// The value none MUST NOT be used as the ID Token alg value unless the Client uses only Response Types
	// that return no ID Token from the Authorization Endpoint (such as when only using the Authorization Code Flow).
	// The default, if omitted, is RS256.
	IDTokenSignedResponseAlg string `json:"id_token_signed_response_alg,omitempty"`

	// IdTokenEncryptedResponseAlg is OPTIONAL. JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
	// If this is requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
	// The default, if omitted, is that no encryption is performed.
	IDTokenEncryptedResponseAlg string `json:"id_token_encrypted_response_alg,omitempty"`

	// IdTokenEncryptedResponseEnc is OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client.
	// If id_token_encrypted_response_alg is specified, the default id_token_encrypted_response_enc value is A128CBC-HS256.
	// When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
	IDTokenEncryptedResponseEnc string `json:"id_token_encrypted_response_enc,omitempty"`

	// UserInfoSignedResponseAlg is OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses.
	// If this is specified, the response will be JWT [JWT] serialized, and signed using JWS.
	// The default, if omitted, is for the UserInfo Response to return the Claims as a UTF-8 [RFC3629] encoded JSON object
	// using the application/json content-type.
	UserInfoSignedResponseAlg string `json:"userinfo_signed_response_alg,omitempty"`

	// UserInfoEncryptedResponseAlg is OPTIONAL. JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
	// If both signing and encryption are requested, the response will be signed then encrypted, with the result being a Nested JWT,
	// as defined in [JWT]. The default, if omitted, is that no encryption is performed.
	UserInfoEncryptedResponseAlg string `json:"userinfo_encrypted_response_alg,omitempty"`

	// UserInfoEncryptedResponseEnc is OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses.
	// If userinfo_encrypted_response_alg is specified, the default userinfo_encrypted_response_enc value is A128CBC-HS256.
	// When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided.
	UserInfoEncryptedResponseEnc string `json:"userinfo_encrypted_response_enc,omitempty"`

	// RequestObjectSigningAlg is OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects
	// sent to the OP. All Request Objects from this Client MUST be rejected, if not signed
	// with this algorithm. Request Objects are described in Section 6.1 of the OpenID Connect
	// Core 1.0 [OpenID.Core].
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`

	// RequestObjectEncryptionAlg is OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for
	// encrypting Request Objects sent to the OP. This parameter SHOULD be included when
	// symmetric encryption will be used, since this signals to the OP that a client_secret
	// value needs to be returned from which the symmetric key will be derived, that might not
	// otherwise be returned. Request Objects are described in Section 6.1 of the OpenID Connect
	// Core 1.0 [OpenID.Core].
	RequestObjectEncryptionAlg string `json:"request_object_encryption_alg,omitempty"`

	// RequestObjectEncryptionEnc is OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting
	// Request Objects sent to the OP. If request_object_encryption_alg is specified, the
	// default for this value is A128CBC-HS256. When request_object_encryption_enc is included,
	// request_object_encryption_alg MUST also be provided. Request Objects are described in
	// Section 6.1 of the OpenID Connect Core 1.0 [OpenID.Core].
	RequestObjectEncryptionEnc string `json:"request_object_encryption_enc,omitempty"`

	// TokenEndpointAuthMethod is OPTIONAL. Requested Client Authentication method for the Token Endpoint.
	// The options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none.
	// If omitted, the default is client_secret_basic.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// TokenEndpointAuthSigningAlg is OPTIONAL. JWS alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to
	// authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt
	// authentication methods. All Token Requests using these authentication methods from this
	// Client MUST be rejected, if the JWT is not signed with this algorithm.
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// DefaultMaxAge is OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be
	// actively authenticated if the End-User was authenticated longer ago than the specified
	// number of seconds. The max_age request parameter overrides this default value. If
	// omitted, no default Maximum Authentication Age is specified.
	DefaultMaxAge *int `json:"default_max_age,omitempty"`

	// RequireAuthTime is OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is
	// REQUIRED. It is REQUIRED when the value is true. (If this is false, the auth_time Claim
	// can still be dynamically requested as an individual Claim for the ID Token using the
	// claims request parameter described in Section 5.5. of the OpenID Connect Core 1.0
	// [OpenID.Core].) If omitted, the default value is false.
	RequireAuthTime *bool `json:"require_auth_time,omitempty"`

	// DefaultACRValues is OPTIONAL. Default requested Authentication Context Class Reference values. Array of
	// strings that specifies the default acr values that the OP is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	// The Authentication Context Class satisfied by the authentication performed is returned as
	// the acr Claim Value in the ID Token. The acr Claim is requested as a Voluntary Claim by
	// this parameter. The acr_values_supported discovery element contains a list of the
	// supported acr values supported by this server. Values specified in the acr_values request
	// parameter or an individual acr Claim request override these default values.
	DefaultACRValues []string `json:"default_acr_values,omitempty"`

	// InitiateLoginURI is OPTIONAL. URI using the https scheme that a third party can use to initiate a login by
	// the RP, as specified in Section 4 of the OpenID Connect Core 1.0 [OpenID.Core]. The URI
	// MUST accept requests via both GET and POST. The Client MUST understand the login_hint
	// and iss parameters and SHOULD support the target_link_uri parameter.
	InitiateLoginURI string `json:"initiate_login_uri,omitempty"`

	// RequestURIs is OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the
	// OP. Servers MAY cache the contents of the files referenced by these URIs and not
	// retrieve them at the time they are used in a request. OPs can require that request_uri
	// values used be pre-registered with the require_request_uri_registration discovery
	// parameter. If the contents of the request file could ever change, these URI values
	// SHOULD include the base64url encoded SHA-256 hash of the file contents referenced by
	// the URI as the value of the uri hash. If the request_uri is a URN, the server SHOULD
	// validate that it is a URN that the server has been configured to accept from this
	// client. The request_uri_parameter_supported discovery parameter can be used to determine
	// if this parameter is supported by the server.
	RequestURIs []string `json:"request_uris,omitempty"`
}

// ClientRegistrationResponse represents the response from a successful client registration.
// Based on OpenID Connect Dynamic Client Registration 1.0 specification.
type ClientRegistrationResponse struct {
	// ClientRegistrationResponse.ClientID is REQUIRED. OAuth 2.0 Client Identifier.
	ClientID string `json:"client_id"`

	// ClientRegistrationResponse.ClientSecret is OPTIONAL. OAuth 2.0 Client Secret. The same requirements for client_secret apply as
	// those in Section 2.1 of OAuth 2.0 [RFC6749]. If this field is omitted, the client
	// defaults to an empty string, i.e., the client will not be able to use the
	// client_secret_basic authentication method but may use any other authentication method
	// if its requirements are met.
	ClientSecret string `json:"client_secret,omitempty"`

	// ClientRegistrationResponse.ClientIDIssuedAt is OPTIONAL. Time at which the Client Identifier was issued. The time is represented as
	// the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`

	// ClientRegistrationResponse.ClientSecretExpiresAt is REQUIRED if client_secret is issued. Time at which the client_secret will expire or 0 if it will not expire.
	// The time is represented as the number of seconds from 1970-01-01T0:0:0Z as measured in
	// UTC until the date/time of expiry.
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`

	// ClientRegistrationResponse.RegistrationAccessToken is OPTIONAL. OAuth 2.0 Client Registration Access Token. This token is used by the Client
	// to perform subsequent operations upon the Client registration, as described in Section
	// 4. The token SHOULD be treated as sensitive data by the Client and protected
	// accordingly. Implementations MUST either return both a Client Configuration Endpoint and
	// a Registration Access Token or neither of them.
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`

	// ClientRegistrationResponse.RegistrationClientURI is OPTIONAL. Location of the Client Configuration Endpoint where the Client can make
	// HTTP requests to perform subsequent operations upon the resulting Client registration.
	// This URL MUST use the https scheme. Implementations MUST either return both a Client
	// Configuration Endpoint and a Registration Access Token or neither of them.
	RegistrationClientURI string `json:"registration_client_uri,omitempty"`
}

// IsExpired returns true if the client secret has expired
func (r *ClientRegistrationResponse) IsExpired() bool {
	if r.ClientSecretExpiresAt == nil {
		return false // No expiration
	}
	return time.Now().Unix() >= *r.ClientSecretExpiresAt
}

// GetClientIDIssuedAt returns the time when the client ID was issued
func (r *ClientRegistrationResponse) GetClientIDIssuedAt() time.Time {
	return time.Unix(r.ClientIDIssuedAt, 0)
}

// GetClientSecretExpiresAt returns the time when the client secret expires, or zero time if no expiration
func (r *ClientRegistrationResponse) GetClientSecretExpiresAt() time.Time {
	if r.ClientSecretExpiresAt == nil || *r.ClientSecretExpiresAt == 0 {
		return time.Time{} // Zero time for no expiration
	}
	return time.Unix(*r.ClientSecretExpiresAt, 0)
}

// ClientRegistrationError represents an error response from the client registration endpoint.
// Based on OpenID Connect Dynamic Client Registration 1.0 specification.
type ClientRegistrationError struct {
	// ClientRegistrationError.ErrorCode is REQUIRED. A single ASCII error code.
	ErrorCode string `json:"error"`

	// ClientRegistrationError.ErrorDescription is OPTIONAL. Human-readable ASCII [USASCII] text providing additional information,
	// used to assist the client developer in understanding the error that occurred.
	ErrorDescription string `json:"error_description,omitempty"`

	// ClientRegistrationError.ErrorURI is OPTIONAL. A URI identifying a human-readable web page with information about the error,
	// used to provide the client developer with additional information about the error.
	ErrorURI string `json:"error_uri,omitempty"`

	Cause error `json:"-"`
}

// Error implements the error interface, returning the error description if available,
// otherwise falling back to the error code.
func (e *ClientRegistrationError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorDescription
	}
	return e.ErrorCode
}

// Unwrap returns the underlying error code for error wrapping.
func (e *ClientRegistrationError) Unwrap() error {
	return e.Cause
}

// Common error codes for client registration
const (
	ErrorInvalidRedirectURI    = "invalid_redirect_uri"
	ErrorInvalidClientMetadata = "invalid_client_metadata"
)
