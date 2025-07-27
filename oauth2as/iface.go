package oauth2as

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2ext/claims"
)

type Authorizer interface {
	// Authorize should be called once the consumer has validated the identity
	// of the user. This will return the appropriate response directly to the
	// passed http context, which should be considered finalized when this is
	// called. Note: This does not have to be the same http request in which
	// Authorization was started, but the session ID field will need to be
	// tracked and consistent.
	//
	// The scopes this request has been granted with should be included.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Authorize(w http.ResponseWriter, r *http.Request, authReqID uuid.UUID, auth *Authorization) error
}

type Authorization struct {
	// Subject that was authenticated
	Subject string `json:"sub"`
	// Scopes are the list of scopes this session was granted
	Scopes []string `json:"scopes"`
	// ACR is the Authentication Context Class Reference the session was
	// authenticated with
	ACR string `json:"acr"`
	// AMR are the Authentication Methods Reference the session was
	// authenticated with
	AMR []string `json:"amr"`
	// Metadata can optionally contain serialized data, that will be made
	// accessible across calls. This library will not maipulate the data.
	Metadata json.RawMessage `json:"metadata"`
}

// AuthorizationRequest details the information the user starting the
// authorization flow requested
type AuthorizationRequest struct {
	// ID for this auth request
	ID uuid.UUID
	// ACRValues are the authentication context class reference values the
	// caller requested
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
	ACRValues []string
	// Scopes that have been requested
	Scopes []string
	// ClientID that started this request
	ClientID string
}

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
}

// UserinfoResponse contains information to response to the userinfo response.
type UserinfoResponse struct {
	// Subject is the sub of the user this request is for.
	Identity *claims.RawIDClaims
}
