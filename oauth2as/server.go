package oauth2as

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
)

const (
	// DefaultCodeValidityTime is used if the CodeValidityTime is not
	// configured.
	DefaultCodeValidityTime = 1 * time.Minute
	// DefaultIDTokenValidity is the default IDTokenValidity time.
	DefaultIDTokenValidity = 1 * time.Hour
	// DefaultsAccessTokenValidity is the default AccessTokenValidity time.
	DefaultsAccessTokenValidity = 1 * time.Hour
)

// Config is used to set the configuration for creating a server instance.
type Config struct {
	// Issuer is the issuer we are serving for.
	Issuer string
	// Storage is the storage backend to use for the server.
	Storage Storage
	Clients ClientSource
	// Signer is used for signing tokens issued by this server. This may
	// optionally implement the [AlgorithmSigner] interface, to allow clients to
	// specify the algorithm they want to use for signing. If not provided, the
	// default jwt.Signer methods are used.
	Signer jwt.Signer
	// Verifier is used for verifying tokens issued by this server, for the
	// userinfo endpoint and other places tokens issued by this server are used.
	Verifier jwt.Verifier

	// DPoPVerifier is used for verifying DPoP proofs on token requests. This is
	// optional - if not provided, DPoP proofs will not be verified or enforced.
	DPoPVerifier *dpop.Verifier

	Logger *slog.Logger

	TokenHandler    TokenHandler
	UserinfoHandler UserinfoHandler

	// CodeValidityTime is the maximum time the authorization code is valid,
	// before it is exchanged for a token (code flow). This should be a short
	// value, as the exchange should generally not take long. Defaults to
	// DefaultCodeValidityTime.
	CodeValidityTime time.Duration
	// IDTokenValidity sets the default validity for issued ID tokens. This can
	// be overridden on a per-request basis.
	IDTokenValidity time.Duration
	// AccessTokenValidity sets the default validity for issued access tokens.
	// This can be overridden on a per-request basis. Must be equal or less to
	// the IDTokenValidity time.
	AccessTokenValidity time.Duration
	// MaxRefreshTime sets the longest time a session can be refreshed for, from
	// the time it was created. This can be overridden on a per-request basis.
	// If 0, refresh tokens will never be issued. This is the default.
	MaxRefreshTime time.Duration
	// RefreshTokenRotationGracePeriod is the time window where an old refresh
	// token remains valid after being rotated. This helps handle network
	// failures where the client might retry with the old token. Defaults to 0
	// (no grace period).
	RefreshTokenRotationGracePeriod time.Duration
}

type Server struct {
	config Config

	logger *slog.Logger

	now func() time.Time
}

func NewServer(c Config) (*Server, error) {
	// perform validations
	if c.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	_, err := url.Parse(c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URL %s: %w", c.Issuer, err)
	}

	if c.Storage == nil {
		return nil, fmt.Errorf("storage is required")
	}
	if c.Clients == nil {
		return nil, fmt.Errorf("clients is required")
	}
	if c.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	if c.Verifier == nil {
		return nil, fmt.Errorf("verifier is required")
	}

	// TODO - relax this with defaults if we can make them work.
	if c.TokenHandler == nil {
		return nil, fmt.Errorf("token handler is required")
	}
	if c.UserinfoHandler == nil {
		return nil, fmt.Errorf("userinfo handler is required")
	}

	// Set defaults

	if c.AccessTokenValidity == 0 {
		c.AccessTokenValidity = DefaultsAccessTokenValidity
	}
	if c.IDTokenValidity == 0 {
		c.IDTokenValidity = DefaultIDTokenValidity
	}
	if c.CodeValidityTime == 0 {
		c.CodeValidityTime = DefaultCodeValidityTime
	}

	// Validate token validity times
	if c.AccessTokenValidity < 0 {
		return nil, fmt.Errorf("access token validity must be positive")
	}
	if c.IDTokenValidity < 0 {
		return nil, fmt.Errorf("ID token validity must be positive")
	}
	if c.CodeValidityTime < 0 {
		return nil, fmt.Errorf("code validity time must be positive")
	}
	if c.MaxRefreshTime < 0 {
		return nil, fmt.Errorf("max refresh time must be positive")
	}
	if c.RefreshTokenRotationGracePeriod < 0 {
		return nil, fmt.Errorf("refresh token rotation grace period must be positive or zero")
	}
	if c.AccessTokenValidity > c.IDTokenValidity {
		return nil, fmt.Errorf("access token validity (%v) must be equal to or less than ID token validity (%v)", c.AccessTokenValidity, c.IDTokenValidity)
	}

	svr := &Server{
		config: c,
		logger: slog.New(slog.DiscardHandler),
		now:    time.Now,
	}

	if c.Logger != nil {
		svr.logger = c.Logger
	}

	return svr, nil
}

func (s *Server) validateTokenClient(ctx context.Context, req *oauth2.TokenRequest, wantClientID string) error {
	// check to see if we're working with the same client
	if wantClientID != req.ClientID {
		return &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "", Cause: fmt.Errorf("code redeemed for wrong client")}
	}

	// validate the client
	cok, err := s.config.Clients.ValidateClientSecret(ctx, req.ClientID, req.ClientSecret)
	if err != nil {
		return &oauth2.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "failed to check client id & secret", Cause: err}

	}
	if !cok {
		return &oauth2.TokenError{ErrorCode: oauth2.TokenErrorCodeUnauthorizedClient, Description: "Invalid client secret"}
	}

	return nil
}

type unauthorizedErr interface {
	error
	Unauthorized() bool
}
