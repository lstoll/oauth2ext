package staticclients

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

var (
	// reValidPublicRedirectUri is a fairly strict regular expression that must
	// match against the redirect URI for a Public client. It intentionally may
	// not match all URLs that are technically valid, but is it meant to match
	// all commonly constructed ones, without inadvertently falling victim to
	// parser bugs or parser inconsistencies (e.g.,
	// https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	reValidPublicRedirectURI = regexp.MustCompile(`\Ahttp://(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?(?:|/[A-Za-z0-9./_-]{0,1000})\z`)
)

// Clients implements the core.ClientSource against a static list of clients.
// The type is tagged, to enable loading from JSON/YAML. This can be created
// directly, or via unserializing / using the ExpandUnmarshal function
type Clients struct {
	// Clients is the list of clients
	Clients []Client `json:"clients" yaml:"client"`
}

// ExpandUnmarshal will take the given JSON, and expand variables inside it from
// the environment using os.Expand (https://pkg.go.dev/os#Expand). This supports
// expansion with defaults, e.g
//
// `{"secret": "${MY_SECRET_VAR:-defaultSecret}"}`
//
// will return a secret of the contents of the MY_SECRET_VAR environment
// variable if it is set, otherwise it will be `defaultSecret`.
//
// The JSON unmarshaling is strict, and will error if it contains unknown fields.
//
// If the input is YAML, it should be converted with
// https://pkg.go.dev/sigs.k8s.io/yaml#YAMLToJSON first.
func ExpandUnmarshal(jsonBytes []byte) (*Clients, error) {
	expanded := os.Expand(string(jsonBytes), getenvWithDefault)

	jd := json.NewDecoder(strings.NewReader(expanded))
	jd.DisallowUnknownFields()

	var c Clients
	if err := jd.Decode(&c); err != nil {
		return nil, fmt.Errorf("unmarshaling: %v", err)
	}

	return &c, nil
}

// Client represents an individual oauth2/oidc client.
type Client struct {
	// ID is the identifier for this client, corresponds to the client ID.
	ID string `json:"id" yaml:"id"`
	// Secrets is a list of valid client secrets for this client. At least
	// one secret is required, unless the client is Public and uses PKCE.
	Secrets []string `json:"clientSecrets" yaml:"clientSecrets"`
	// RedirectURLS is a list of valid redirect URLs for this client. At least
	// one is required, unless the client is public a PermitLocalhostRedirect is
	// true. These are an exact match
	RedirectURLs []string `json:"redirectURLs" yaml:"redirectURLs"`
	// Public indicates that this client is public. A "public" client is one who
	// can't keep their credentials confidential.
	// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
	Public bool `json:"public" yaml:"public"`
	// PermitLocalhostRedirect allows redirects to localhost, if this is a
	// public client
	PermitLocalhostRedirect bool `json:"permitLocalhostRedirect" yaml:"permitLocalhostRedirect"`
	// RequiresPKCE indicates that this client should be required to use PKCE
	// for the token exchange. This defaults to true for public clients, and
	// false for non-public clients.
	RequiresPKCE *bool `json:"requiresPKCE" yaml:"requiresPKCE"`
}

func (c *Clients) IsValidClientID(clientID string) (ok bool, err error) {
	_, ok = c.getClient(clientID)
	return ok, nil
}

func (c *Clients) RequiresPKCE(clientID string) (ok bool, err error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}

	if cl.RequiresPKCE == nil {
		// not set. required if public, not if not
		return cl.Public, nil
	}

	return *cl.RequiresPKCE, nil
}

func (c *Clients) ValidateClientSecret(clientID, clientSecret string) (ok bool, err error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}

	if len(cl.Secrets) == 0 && cl.Public && (cl.RequiresPKCE == nil || !*cl.RequiresPKCE) {
		// we're a public client with no secrets and using PKCE. It's valid
		return true, nil
	}

	return slices.ContainsFunc(cl.Secrets, func(s string) bool {
		return subtle.ConstantTimeCompare([]byte(s), []byte(clientSecret)) == 1
	}), nil
}

func (c *Clients) ValidateClientRedirectURI(clientID, redirectURI string) (ok bool, err error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}

	if cl.Public && cl.PermitLocalhostRedirect && reValidPublicRedirectURI.MatchString(redirectURI) {
		// this is a valid public redirect for a client who allows it, all good
		return true, nil
	}

	return slices.Contains(cl.RedirectURLs, redirectURI), nil
}

func (c *Clients) getClient(id string) (Client, bool) {
	for _, c := range c.Clients {
		if c.ID == id {
			return c, true
		}
	}
	return Client{}, false
}

// getenvWithDefault maps FOO:-default to $FOO or default if $FOO is unset or
// null.
func getenvWithDefault(key string) string {
	parts := strings.SplitN(key, ":-", 2)
	val := os.Getenv(parts[0])
	if val == "" && len(parts) == 2 {
		val = parts[1]
	}
	return val
}
