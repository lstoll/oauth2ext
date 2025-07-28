package oauth2as

import (
	"context"
	"net/url"
)

// ClientOpt is a flag that can be set on a given client, to adjust various
// behaviours.
type ClientOpt string

const (
	// ClientOptSkipPKCE indicates that the client is not required to use PKCE
	ClientOptSkipPKCE ClientOpt = "skip-pkce"
)

// ClientSource is used for validating client informantion for the general flow
type ClientSource interface {
	// IsValidClientID should return true if the passed client ID is valid
	IsValidClientID(_ context.Context, clientID string) (ok bool, err error)
	// ValidateClientSecret should confirm if the passed secret is valid for the
	// given client. If no secret is provided, clientSecret will be empty but
	// this will still be called.
	ValidateClientSecret(_ context.Context, clientID, clientSecret string) (ok bool, err error)
	// ValidateRedirectURI should return the list of valid redirect URIs. They
	// will be compared for an exact match, with the exception of loopback
	// addresses, which can have a variable port
	// (https://www.rfc-editor.org/rfc/rfc8252#section-7.3).
	RedirectURIs(_ context.Context, clientID string) ([]string, error)
	// ClientOpts returns the list of options for this client. See ClientOpt.
	ClientOpts(_ context.Context, clientID string) ([]ClientOpt, error)
}

// isValidRedirectURI compares a redirect URI from a request against a list of
// registered URIs, conforming to OAuth 2.1 specifications.
//
// It performs a simple string comparison as required by RFC 3986. It also
// handles the special case for native app loopback URIs (http://127.0.0.1,
// http://localhost, or http://[::1]) where the port number can be variable,
// as specified in RFC 8252, Section 7.3.
//
// - redirectURI: The URI from the incoming authorization request.
// - registeredURIs: A slice of URIs registered for the client.
//
// Returns true if a valid match is found, otherwise false.
func isValidRedirectURI(redirectURI string, registeredURIs []string) bool {
	isLoopbackHost := func(hostname string) bool {
		return hostname == "127.0.0.1" || hostname == "::1"
	}

	for _, registeredURI := range registeredURIs {
		// direct string comparison
		if redirectURI == registeredURI {
			return true
		}

		// check for the loopback exception
		reqURL, err := url.Parse(redirectURI)
		if err != nil {
			continue
		}

		regURL, err := url.Parse(registeredURI)
		if err != nil {
			continue
		}

		// Check if both are HTTP loopback URIs.
		isReqLoopback := reqURL.Scheme == "http" && isLoopbackHost(reqURL.Hostname())
		isRegLoopback := regURL.Scheme == "http" && isLoopbackHost(regURL.Hostname())

		if isReqLoopback && isRegLoopback {
			// For loopback URIs, we ignore the port and the exact IP protocol.
			// To do this safely, we normalize both URIs by replacing the Host
			// (e.g., "127.0.0.1:1234") with just the hostname "localhost" and
			// then compare the string representations. This correctly compares
			// all other parts (scheme, userinfo, path, query).
			reqURL.Host = "localhost"
			regURL.Host = "localhost"

			if reqURL.String() == regURL.String() {
				return true
			}
		}
	}

	// No match found after checking all registered URIs.
	return false
}
