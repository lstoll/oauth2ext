package oauth2as

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/internal/th"
	"lds.li/oauth2ext/oauth2as/internal/oauth2"
)

type UserinfoHandler func(ctx context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error)

// UserinfoRequest contains information about this request to the UserInfo
// endpoint
type UserinfoRequest struct {
	// Subject is the sub of the user this request is for.
	Subject string
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
		be := &oauth2.BearerError{} // no content, just request auth
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO: Implement scope and audience validation on the access token

	atJWT, err := s.verifyAccessToken(authSp[1])
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		be := &oauth2.BearerError{Code: oauth2.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	atSub, err := atJWT.Subject()
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		be := &oauth2.BearerError{Code: oauth2.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		Subject: atSub,
	}

	w.Header().Set("Content-Type", "application/json")

	// TODO: Return an error if UserinfoHandler is not configured
	uiresp, err := s.config.UserinfoHandler(req.Context(), uireq)
	if err != nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "error in user handler"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}
	if uiresp.Identity == nil {
		herr := &oauth2.HTTPError{Code: http.StatusInternalServerError, Cause: err, CauseMsg: "userinfo has no identity"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO: Pre-populate standard claims (iss, aud, etc.) in the identity response

	if err := json.NewEncoder(w).Encode(uiresp.Identity); err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}
}

func (s *Server) verifyAccessToken(compact string) (*jwt.VerifiedJWT, error) {
	valid, err := jwt.NewValidator(&jwt.ValidatorOpts{
		ExpectedIssuer:     &s.config.Issuer,
		ExpectedTypeHeader: th.Ptr("at+jwt"),
		IgnoreAudiences:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating validator: %w", err)
	}
	vjwt, err := s.config.Verifier.VerifyAndDecode(compact, valid)
	if err != nil {
		return nil, fmt.Errorf("verifying and decoding access token: %w", err)
	}
	return vjwt, nil
}
