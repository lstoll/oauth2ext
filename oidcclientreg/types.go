package oidcclientreg

import (
	"time"
)

// ClientRegistrationRequest represents the client metadata sent during dynamic client registration.
// Based on OpenID Connect Dynamic Client Registration 1.0 specification.
type ClientRegistrationRequest struct {
	// ClientRegistrationRequest.RedirectURIs is REQUIRED. Array of Redirection URI values used by the Client.
	// One of these registered Redirection URI values MUST exactly match the redirect_uri parameter
	// value used in each Authorization Request, with the matching performed as described in
	// Section 6.2.1 of RFC3986 (Simple String Comparison).
	RedirectURIs []string `json:"redirect_uris"`

	// ClientRegistrationRequest.ResponseTypes is OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client
	// is declaring that it will restrict itself to using. If omitted, the default is that the
	// Client will use only the "code" Response Type.
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientRegistrationRequest.GrantTypes is OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is
	// declaring that it will restrict itself to using. If omitted, the default is that the Client
	// will use only the "authorization_code" Grant Type.
	GrantTypes []string `json:"grant_types,omitempty"`

	// ClientRegistrationRequest.ApplicationType is OPTIONAL. Kind of the application. The defined values are "native" or "web".
	// Web Clients using the OAuth Implicit Grant Type MUST only register URLs using the https
	// scheme as redirect_uris; they MUST NOT use localhost as the hostname.
	// Native Clients MUST only register redirect_uris using custom URI schemes or URLs using the
	// http scheme with localhost as the hostname.
	ApplicationType string `json:"application_type,omitempty"`

	// ClientRegistrationRequest.Contacts is OPTIONAL. Array of e-mail addresses of people responsible for this Client.
	// This might be used by some providers to enable a Web user interface to modify the Client
	// information.
	Contacts []string `json:"contacts,omitempty"`

	// ClientRegistrationRequest.ClientName is OPTIONAL. Name of the Client to be presented to the End-User.
	// If desired, representation of this name in multiple languages and scripts is provided
	// using the structure described in Section 2.1.
	ClientName string `json:"client_name,omitempty"`

	// ClientRegistrationRequest.LogoURI is OPTIONAL. URL that references a logo for the Client application. If present, the server
	// SHOULD display this image to the End-User during approval. The value of this field MUST
	// point to a valid image file. If desired, representation of this logo in multiple languages
	// and scripts is provided using the structure described in Section 2.1.
	LogoURI string `json:"logo_uri,omitempty"`

	// ClientRegistrationRequest.ClientURI is OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a
	// valid Web page. If desired, representation of this URL in multiple languages and scripts
	// is provided using the structure described in Section 2.1.
	ClientURI string `json:"client_uri,omitempty"`

	// ClientRegistrationRequest.PolicyURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// how the profile data will be used. The value of this field MUST point to a valid web page.
	// If desired, representation of this URL in multiple languages and scripts is provided using
	// the structure described in Section 2.1.
	PolicyURI string `json:"policy_uri,omitempty"`

	// ClientRegistrationRequest.TermsOfServiceURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// Relying Party's terms of service. The value of this field MUST point to a valid web page.
	// If desired, representation of this URL in multiple languages and scripts is provided using
	// the structure described in Section 2.1.
	TermsOfServiceURI string `json:"terms_of_service_uri,omitempty"`

	// ClientRegistrationRequest.JwksURI is OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs
	// requests to the Server, it contains the signing key(s) the Server uses to validate
	// signatures from the Client. The JWK Set MAY also contain the Client's encryption keys(s),
	// which are used by the Server to encrypt responses to the Client. When both signing and
	// encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all
	// keys in the referenced JWK Set to indicate each key's intended usage.
	JwksURI string `json:"jwks_uri,omitempty"`

	// ClientRegistrationRequest.Jwks is OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the
	// jwks parameter are the same as the jwks_uri parameter, other than the JWK Set is passed
	// by value, rather than by reference. This parameter is intended only to be used by Clients
	// that, for some reason, cannot use the jwks_uri parameter, for instance, by native
	// applications that might not have a location to host the contents of the JWK Set. If a
	// Client can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that
	// it does not enable key rotation (which jwks_uri does, as described in Section 10 of
	// OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri and jwks parameters MUST NOT be
	// used together.
	Jwks interface{} `json:"jwks,omitempty"`

	// ClientRegistrationRequest.SectorIdentifierURI is OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers
	// by the OP. The URL references a file with a single JSON array of redirect_uri values.
	// Please see Section 5. of the OpenID Connect Core 1.0 [OpenID.Core] for more details.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// ClientRegistrationRequest.SubjectType is OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported
	// Discovery parameter contains a list of the supported subject_type values for this server.
	// Valid types include "pairwise" and "public".
	SubjectType string `json:"subject_type,omitempty"`

	// ClientRegistrationRequest.RequestObjectSigningAlg is OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects
	// sent to the OP. All Request Objects from this Client MUST be rejected, if not signed
	// with this algorithm. Request Objects are described in Section 6.1 of the OpenID Connect
	// Core 1.0 [OpenID.Core].
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`

	// ClientRegistrationRequest.RequestObjectEncryptionAlg is OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for
	// encrypting Request Objects sent to the OP. This parameter SHOULD be included when
	// symmetric encryption will be used, since this signals to the OP that a client_secret
	// value needs to be returned from which the symmetric key will be derived, that might not
	// otherwise be returned. Request Objects are described in Section 6.1 of the OpenID Connect
	// Core 1.0 [OpenID.Core].
	RequestObjectEncryptionAlg string `json:"request_object_encryption_alg,omitempty"`

	// ClientRegistrationRequest.RequestObjectEncryptionEnc is OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting
	// Request Objects sent to the OP. If request_object_encryption_alg is specified, the
	// default for this value is A128CBC-HS256. When request_object_encryption_enc is included,
	// request_object_encryption_alg MUST also be provided. Request Objects are described in
	// Section 6.1 of the OpenID Connect Core 1.0 [OpenID.Core].
	RequestObjectEncryptionEnc string `json:"request_object_encryption_enc,omitempty"`

	// ClientRegistrationRequest.TokenEndpointAuthSigningAlg is OPTIONAL. JWS alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to
	// authenticate the Client at the Token Endpoint for the private_key_jwt and client_secret_jwt
	// authentication methods. All Token Requests using these authentication methods from this
	// Client MUST be rejected, if the JWT is not signed with this algorithm.
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// ClientRegistrationRequest.DefaultMaxAge is OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be
	// actively authenticated if the End-User was authenticated longer ago than the specified
	// number of seconds. The max_age request parameter overrides this default value. If
	// omitted, no default Maximum Authentication Age is specified.
	DefaultMaxAge *int `json:"default_max_age,omitempty"`

	// ClientRegistrationRequest.RequireAuthTime is OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is
	// REQUIRED. It is REQUIRED when the value is true. (If this is false, the auth_time Claim
	// can still be dynamically requested as an individual Claim for the ID Token using the
	// claims request parameter described in Section 5.5. of the OpenID Connect Core 1.0
	// [OpenID.Core].) If omitted, the default value is false.
	RequireAuthTime *bool `json:"require_auth_time,omitempty"`

	// ClientRegistrationRequest.DefaultACRValues is OPTIONAL. Default requested Authentication Context Class Reference values. Array of
	// strings that specifies the default acr values that the OP is being requested to use for
	// processing requests from this Client, with the values appearing in order of preference.
	// The Authentication Context Class satisfied by the authentication performed is returned as
	// the acr Claim Value in the ID Token. The acr Claim is requested as a Voluntary Claim by
	// this parameter. The acr_values_supported discovery element contains a list of the
	// supported acr values supported by this server. Values specified in the acr_values request
	// parameter or an individual acr Claim request override these default values.
	DefaultACRValues []string `json:"default_acr_values,omitempty"`

	// ClientRegistrationRequest.InitiateLoginURI is OPTIONAL. URI using the https scheme that a third party can use to initiate a login by
	// the RP, as specified in Section 4 of the OpenID Connect Core 1.0 [OpenID.Core]. The URI
	// MUST accept requests via both GET and POST. The Client MUST understand the login_hint
	// and iss parameters and SHOULD support the target_link_uri parameter.
	InitiateLoginURI string `json:"initiate_login_uri,omitempty"`

	// ClientRegistrationRequest.RequestURIs is OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the
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

	// ClientRegistrationResponse.ClientIDIssuedAt is REQUIRED. Time at which the Client Identifier was issued. The time is represented as
	// the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
	ClientIDIssuedAt int64 `json:"client_id_issued_at"`

	// ClientRegistrationResponse.ClientSecretExpiresAt is OPTIONAL. Time at which the client_secret will expire or 0 if it will not expire.
	// The time is represented as the number of seconds from 1970-01-01T0:0:0Z as measured in
	// UTC until the date/time of expiry.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`

	// ClientRegistrationResponse.RegistrationAccessToken is REQUIRED. OAuth 2.0 Client Registration Access Token. This token is used by the Client
	// to perform subsequent operations upon the Client registration, as described in Section
	// 4. The token SHOULD be treated as sensitive data by the Client and protected
	// accordingly.
	RegistrationAccessToken string `json:"registration_access_token"`

	// ClientRegistrationResponse.RegistrationClientURI is REQUIRED. Location of the Client Configuration Endpoint where the Client can make
	// HTTP requests to perform subsequent operations upon the resulting Client registration.
	// Implementations MUST support both GET and POST requests to this endpoint.
	RegistrationClientURI string `json:"registration_client_uri"`

	// ClientRegistrationResponse.Scope is OPTIONAL. Array of OAuth 2.0 scope values that the Client can use when requesting
	// access tokens. The semantics of values in this list are service specific. If omitted,
	// an authorization server may register a client with a default set of scopes.
	Scope string `json:"scope,omitempty"`

	// ClientRegistrationResponse.GrantTypes is OPTIONAL. Array of OAuth 2.0 Grant Type names that the Client is restricted to using.
	// If omitted, the default is that the Client will use only the "authorization_code"
	// Grant Type.
	GrantTypes []string `json:"grant_types,omitempty"`

	// ClientRegistrationResponse.ResponseTypes is OPTIONAL. Array of the OAuth 2.0 response_type values that the Client is restricted to
	// using. If omitted, the default is that the Client will use only the "code" Response
	// Type.
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientRegistrationResponse.ApplicationType is OPTIONAL. Kind of the application. The defined values are "native" or "web".
	ApplicationType string `json:"application_type,omitempty"`

	// ClientRegistrationResponse.Contacts is OPTIONAL. Array of e-mail addresses of people responsible for this Client.
	Contacts []string `json:"contacts,omitempty"`

	// ClientRegistrationResponse.ClientName is OPTIONAL. Name of the Client to be presented to the End-User.
	ClientName string `json:"client_name,omitempty"`

	// ClientRegistrationResponse.LogoURI is OPTIONAL. URL that references a logo for the Client application.
	LogoURI string `json:"logo_uri,omitempty"`

	// ClientRegistrationResponse.ClientURI is OPTIONAL. URL of the home page of the Client.
	ClientURI string `json:"client_uri,omitempty"`

	// ClientRegistrationResponse.PolicyURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// how the profile data will be used.
	PolicyURI string `json:"policy_uri,omitempty"`

	// ClientRegistrationResponse.TermsOfServiceURI is OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the
	// Relying Party's terms of service.
	TermsOfServiceURI string `json:"terms_of_service_uri,omitempty"`

	// ClientRegistrationResponse.JwksURI is OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document.
	JwksURI string `json:"jwks_uri,omitempty"`

	// ClientRegistrationResponse.Jwks is OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value.
	Jwks interface{} `json:"jwks,omitempty"`

	// ClientRegistrationResponse.SectorIdentifierURI is OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers
	// by the OP.
	SectorIdentifierURI string `json:"sector_identifier_uri,omitempty"`

	// ClientRegistrationResponse.SubjectType is OPTIONAL. subject_type requested for responses to this Client.
	SubjectType string `json:"subject_type,omitempty"`

	// ClientRegistrationResponse.RequestObjectSigningAlg is OPTIONAL. JWS alg algorithm that MUST be used for signing Request Objects sent to the OP.
	RequestObjectSigningAlg string `json:"request_object_signing_alg,omitempty"`

	// ClientRegistrationResponse.RequestObjectEncryptionAlg is OPTIONAL. JWE alg algorithm the RP is declaring that it may use for encrypting Request Objects.
	RequestObjectEncryptionAlg string `json:"request_object_encryption_alg,omitempty"`

	// ClientRegistrationResponse.RequestObjectEncryptionEnc is OPTIONAL. JWE enc algorithm the RP is declaring that it may use for encrypting Request Objects.
	RequestObjectEncryptionEnc string `json:"request_object_encryption_enc,omitempty"`

	// ClientRegistrationResponse.TokenEndpointAuthSigningAlg is OPTIONAL. JWS alg algorithm that MUST be used for signing the JWT used to authenticate the Client.
	TokenEndpointAuthSigningAlg string `json:"token_endpoint_auth_signing_alg,omitempty"`

	// ClientRegistrationResponse.DefaultMaxAge is OPTIONAL. Default Maximum Authentication Age.
	DefaultMaxAge *int `json:"default_max_age,omitempty"`

	// ClientRegistrationResponse.RequireAuthTime is OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED.
	RequireAuthTime *bool `json:"require_auth_time,omitempty"`

	// ClientRegistrationResponse.DefaultACRValues is OPTIONAL. Default requested Authentication Context Class Reference values.
	DefaultACRValues []string `json:"default_acr_values,omitempty"`

	// ClientRegistrationResponse.InitiateLoginURI is OPTIONAL. URI using the https scheme that a third party can use to initiate a login by the RP.
	InitiateLoginURI string `json:"initiate_login_uri,omitempty"`

	// ClientRegistrationResponse.RequestURIs is OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP.
	RequestURIs []string `json:"request_uris,omitempty"`

	// ClientRegistrationResponse.RedirectURIs is REQUIRED. Array of Redirection URI values used by the Client.
	RedirectURIs []string `json:"redirect_uris"`
}

// IsExpired returns true if the client secret has expired
func (r *ClientRegistrationResponse) IsExpired() bool {
	if r.ClientSecretExpiresAt == 0 {
		return false // No expiration
	}
	return time.Now().Unix() >= r.ClientSecretExpiresAt
}

// GetClientIDIssuedAt returns the time when the client ID was issued
func (r *ClientRegistrationResponse) GetClientIDIssuedAt() time.Time {
	return time.Unix(r.ClientIDIssuedAt, 0)
}

// GetClientSecretExpiresAt returns the time when the client secret expires, or zero time if no expiration
func (r *ClientRegistrationResponse) GetClientSecretExpiresAt() time.Time {
	if r.ClientSecretExpiresAt == 0 {
		return time.Time{} // Zero time for no expiration
	}
	return time.Unix(r.ClientSecretExpiresAt, 0)
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
