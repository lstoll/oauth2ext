package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Storage is used to track the state of the session across it's
// lifecycle.
type Storage interface {
	// // NewID should return a new, unique identifier to be used for a session. It
	// // should be hard to guess/brute force
	// NewID() string
	// // GetSession should return the current session state for the given session
	// // ID. It should be deserialized/written in to into. If the session does not
	// // exist, found should be false with no error.
	// GetSession(ctx context.Context, sessionID string, into Session) (found bool, err error)
	// // PutSession should persist the new state of the session
	// PutSession(context.Context, Session) error
	// // DeleteSession should remove the corresponding session.
	// DeleteSession(ctx context.Context, sessionID string) error

	GetAuthRequest(ctx context.Context, id uuid.UUID) (*AuthRequest, error)
	PutAuthRequest(ctx context.Context, ar *AuthRequest) error
	DeleteAuthRequest(ctx context.Context, id uuid.UUID) error

	GetAuthCode(ctx context.Context, id uuid.UUID) (*AuthCode, error)
	PutAuthCode(ctx context.Context, ac *AuthCode) error
	DeleteAuthCode(ctx context.Context, id uuid.UUID) error

	GetRefreshSession(ctx context.Context, id uuid.UUID) (*RefreshSession, error)
	PutRefreshSession(ctx context.Context, ac *RefreshSession) error
	DeleteRefreshSession(ctx context.Context, id uuid.UUID) error
}

// type sessionStage string

// const (
// 	// A request to authenticate someone has been received, but upstream has not
// 	// authenticated the user.
// 	sessionStageRequested sessionStage = "requested"
// 	// Code flow was requested, and a code has been issued.
// 	sessionStageCode sessionStage = "code"
// 	// An access token has been issued to the user, but the session is not for
// 	// offline access (aka no refresh token)
// 	sessionStageAccessTokenIssued sessionStage = "access_token_issued"
// 	// An access token has been issued, along with a refresh token.
// 	sessionStageRefreshable sessionStage = "refreshable"
// )

type AuthRequestResponseType string

const (
	AuthRequestResponseTypeUnknown AuthRequestResponseType = "unknown"
	AuthRequestResponseTypeCode    AuthRequestResponseType = "code"
	AuthRequestResponseTypeToken   AuthRequestResponseType = "token"
)

// AuthRequest represents the information that the caller requested
// authentication with. This is used up until the point that the user is
// authenticated, at which point it is discarded.
type AuthRequest struct {
	// ID is the unique identifier for this request.
	ID uuid.UUID `json:"id,omitempty"`
	// ClientID requested for this request.
	ClientID string `json:"client_id,omitempty"`

	RedirectURI string `json:"redirect_uri,omitempty"`

	State        string                  `json:"state,omitempty"`
	Scopes       []string                `json:"scopes,omitempty"`
	Nonce        string                  `json:"nonce,omitempty"`
	ResponseType AuthRequestResponseType `json:"response_type,omitempty"`
	// CodeChallenge is the PKCE code challenge, if it was passed when the flow
	// was started.
	CodeChallenge string   `json:"code_challenge,omitempty"`
	ACRValues     []string `json:"acr_values,omitempty"`
	// Expiry time of this request
	Expiry time.Time `json:"expiry,omitempty"`
}

// Authorization tracks the information a session was actually authorized for.
// It is accessible from the token and refresh calls.
type Authorization struct {
	// ID is a unqique identifier for this authorization
	ID uuid.UUID `json:"id"`
	// RequestID contains the ID of the request this authorization was generated
	// from, for audit purposes.
	AuthReqID uuid.UUID `json:"auth_req_id"`
	// Subject that was authenticated
	Subject string `json:"sub"`
	// ClientID that this authentication is for
	ClientID string `json:"client_id,omitempty"`
	// Scopes are the list of scopes this session was granted
	Scopes []string `json:"scopes"`
	// ACR is the Authentication Context Class Reference the session was
	// authenticated with
	ACR string `json:"acr"`
	// AMR are the Authentication Methods Reference the session was
	// authenticated with
	AMR []string `json:"amr"`
	// AuthenticatedAt is the time which authentication occured
	AuthenticatedAt time.Time
	// Nonce that was provided during the flow
	Nonce string `json:"nonce,omitempty"`
	// Metadata can optionally contain serialized data, that will be made
	// accessible across calls. This library will not maipulate the data.
	Metadata json.RawMessage `json:"metadata"`
}

// AuthCode tracks the stage where a user is authenticated, but has not
// exchanged the code for a token yet
type AuthCode struct {
	ID uuid.UUID `json:"id"`
	// Authorization data for this code.
	Authorization *Authorization `json:"authorization,omitempty"`
	// Code is the server part of the bcrypt code
	Code []byte `json:"code,omitempty"`
	// CodeChallenge is the PKCE code challenge, if it was passed when the flow
	// was started.
	CodeChallenge string `json:"code_challenge,omitempty"`

	Expiry time.Time `json:"expiry,omitempty"`
}

// RefreshSession represents a user that was authenticated, and has a session
// that is refreshable.
type RefreshSession struct {
	ID uuid.UUID `json:"id,omitempty"`
	// Authorization data for this code.
	Authorization *Authorization `json:"authorization,omitempty"`
	// The currently valid refresh token for this session.
	RefreshToken []byte `json:"refresh_token,omitempty"`
	// The time the whole session should be expired at. It should be garbage
	// collected at this time.
	Expiry time.Time `json:"expiry,omitempty"`
}
