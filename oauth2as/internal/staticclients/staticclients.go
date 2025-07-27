package staticclients

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/lstoll/oauth2as"
)

// Clients implements the oidcop.ClientSource against a static list of clients.
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
	// Opts is the list of options for this client.
	Opts []oauth2as.ClientOpt `json:"opts" yaml:"opts"`
}

func (c *Clients) IsValidClientID(_ context.Context, clientID string) (ok bool, err error) {
	_, ok = c.getClient(clientID)
	return ok, nil
}

func (c *Clients) ClientOpts(_ context.Context, clientID string) ([]oauth2as.ClientOpt, error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return nil, fmt.Errorf("invalid client ID")
	}

	return cl.Opts, nil
}

func (c *Clients) ValidateClientSecret(_ context.Context, clientID, clientSecret string) (ok bool, err error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}
	if !ok {
		return false, fmt.Errorf("invalid client ID")
	}

	if len(cl.Secrets) == 0 && cl.Public && slices.Contains(cl.Opts, oauth2as.ClientOptSkipPKCE) {
		// we're a public client with no secrets and using PKCE. It's valid
		return true, nil
	}

	return slices.ContainsFunc(cl.Secrets, func(s string) bool {
		return subtle.ConstantTimeCompare([]byte(s), []byte(clientSecret)) == 1
	}), nil
}

func (c *Clients) RedirectURIs(_ context.Context, clientID string) ([]string, error) {
	cl, ok := c.getClient(clientID)
	if !ok {
		return nil, fmt.Errorf("invalid client ID")
	}

	return cl.RedirectURLs, nil
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
