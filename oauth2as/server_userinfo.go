package oauth2as

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2as/oauth2proto"
	"lds.li/oauth2ext/oidc"
)

type UserinfoHandler func(ctx context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error)

// UserinfoRequest contains information about this request to the UserInfo
// endpoint. The handler is responsible for returning only claims permitted by
// GrantedScopes.
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
	// GrantID is the ID of the grant associated with the access token, when
	// present in the token's grid claim.
	GrantID string
	// Metadata is unencrypted application metadata from the grant, when the
	// grant could be loaded from storage.
	Metadata []byte
	// GrantedScopes are the scopes granted on the associated grant.
	GrantedScopes []string
	// ACR is the Authentication Context Class Reference from the grant.
	ACR string
	// AMR lists the Authentication Methods References from the grant.
	AMR []string
}

// UserinfoResponse contains information to response to the userinfo response.
type UserinfoResponse struct {
	// Identity is the identity of the user this request is for, to be JSON
	// serialized.
	Identity any
}

// UserinfoHandler can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// appropriate response data in JSON format to the passed writer.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (s *Server) UserinfoHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &oauth2proto.BearerError{} // no content, just request auth
		herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	// TODO: Implement scope and audience validation on the access token

	atJWT, err := s.verifyAccessToken(req.Context(), authSp[1])
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	atSub, err := atJWT.Subject()
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		Subject: atSub,
	}

	if atJWT.HasString(claimGrantID) {
		grantID, err := atJWT.String(claimGrantID)
		if err != nil {
			slog.ErrorContext(req.Context(), "invalid access token grant ID claim", "error", err)
			be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
			herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
			_ = oauth2proto.WriteError(w, req, herr)
			return
		}

		grant, err := s.config.Storage.GetGrant(req.Context(), grantID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				slog.WarnContext(req.Context(), "grant not found for access token", "grantID", grantID)
			} else {
				slog.ErrorContext(req.Context(), "failed to load grant for userinfo", "grantID", grantID, "error", err)
				herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error loading grant"}
				_ = oauth2proto.WriteError(w, req, herr)
				return
			}
		} else {
			tokenClientID, clientIDErr := atJWT.String("client_id")
			if clientIDErr != nil || tokenClientID != grant.ClientID {
				be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInvalidToken, Description: "invalid access token"}
				herr := &oauth2proto.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: clientIDErr, CauseMsg: "access token client_id mismatch"}
				_ = oauth2proto.WriteError(w, req, herr)
				return
			}
			if !slices.Contains(grant.GrantedScopes, oidc.ScopeOpenID) {
				be := &oauth2proto.BearerError{Code: oauth2proto.BearerErrorCodeInsufficientScope, Description: "openid scope required"}
				herr := &oauth2proto.HTTPError{Code: http.StatusForbidden, WWWAuthenticate: be.String(), CauseMsg: "openid scope required"}
				_ = oauth2proto.WriteError(w, req, herr)
				return
			}
			uireq.GrantID = grantID
			uireq.Metadata = bytes.Clone(grant.Metadata)
			uireq.GrantedScopes = slices.Clone(grant.GrantedScopes)
			uireq.ACR = grant.ACR
			uireq.AMR = slices.Clone(grant.AMR)
		}
	}

	w.Header().Set("Content-Type", "application/json")

	uiresp, err := s.config.UserinfoHandler(req.Context(), uireq)
	if err != nil {
		herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}
	if uiresp.Identity == nil {
		herr := &oauth2proto.HTTPError{Code: http.StatusInternalServerError, CauseMsg: "userinfo has no identity"}
		_ = oauth2proto.WriteError(w, req, herr)
		return
	}

	// TODO: Pre-populate standard claims (iss, aud, etc.) in the identity response

	if err := json.NewEncoder(w).Encode(uiresp.Identity); err != nil {
		_ = oauth2proto.WriteError(w, req, err)
		return
	}
}

func (s *Server) verifyAccessToken(ctx context.Context, compact string) (*jwt.VerifiedJWT, error) {
	vjwt, err := s.config.Verifier.VerifyJWT(ctx, compact, jwt.ValidationPolicy{
		ExpectedIssuer:    s.config.Issuer,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []jwt.Algorithm{s.accessTokenSigningAlgorithm()},
		ExpectedType:      "at+jwt",
		ClockSkew:         jwt.DefaultClockSkew,
		RequireIssuedAt:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying and decoding access token: %w", err)
	}
	return vjwt, nil
}
