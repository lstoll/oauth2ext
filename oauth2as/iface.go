package oidcop

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oidcop/storage"
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

type AuthHandlers interface {
	// SetAuthorizer sets the authorizer these handlers should use to finalize
	// login flows. This will be called before any other methods are called.
	SetAuthorizer(Authorizer)
	StartAuthorization(w http.ResponseWriter, req *http.Request, authReq *AuthorizationRequest)
	Token(req *TokenRequest) (*TokenResponse, error)
	RefreshToken(req *RefreshTokenRequest) (*TokenResponse, error)
	Userinfo(w io.Writer, uireq *UserinfoRequest) (*UserinfoResponse, error)
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

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// Authorization information this session was authorized with
	Authorization storage.Authorization
}

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type RefreshTokenRequest struct {
	// Authorization information this session was authorized with
	Authorization storage.Authorization
}

// Identity of a user, used to construct ID token claims and UserInfo responses.
// Depending on the requested scopes, only a subset of this information might be
// used
type Identity struct {
	EMail    string
	FullName string
	// Extra claims to include in the ID Token.
	ExtraClaims map[string]any
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// OverrideRefreshTokenIssuance can be used to override issuing a refresh
	// token if the client requested it, if true.
	OverrideRefreshTokenIssuance bool

	// OverrideRefreshTokenExpiry can be used to override the expiration of the
	// refresh token. If not set, the default will be used.
	OverrideRefreshTokenExpiry time.Time

	// may be zero, if so defaulted
	IDTokenExpiry     time.Time
	AccessTokenExpiry time.Time

	// Identity sets the user information, that can be included in the returned
	// ID token.
	Identity *Identity

	// AccessTokenExtraClaims sets additional claims to be included in the
	// access token.
	AccessTokenExtraClaims map[string]any

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, if one is issued. If zero, the default will be used.
	RefreshTokenValidUntil time.Time
}

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
}

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoResponse struct {
	// Subject is the sub of the user this request is for.
	Identity *Identity
}

func (a *Authorization) toStorage(authReqID uuid.UUID, clientID string, authenticatedAt time.Time, nonce string) *storage.Authorization {
	return &storage.Authorization{
		ID:              uuid.Must(uuid.NewRandom()),
		AuthReqID:       authReqID,
		Subject:         a.Subject,
		ClientID:        clientID,
		Scopes:          a.Scopes,
		ACR:             a.ACR,
		AMR:             a.AMR,
		AuthenticatedAt: authenticatedAt,
		Nonce:           nonce,
		Metadata:        a.Metadata,
	}
}
