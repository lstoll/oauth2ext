package oauth2as

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oauth2as/internal/oauth2"
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
	// Subject is the sub of the user this request is for.
	Identity *jwt.IDClaims
}

// Userinfo can handle a request to the userinfo endpoint. If the request is not
// valid, an error will be returned. Otherwise handler will be invoked with
// information about the requestor passed in. This handler should write the
// appropriate response data in JSON format to the passed writer.
//
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (s *Server) Userinfo(w http.ResponseWriter, req *http.Request) {
	authSp := strings.SplitN(req.Header.Get("authorization"), " ", 2)
	if !strings.EqualFold(authSp[0], "bearer") || len(authSp) != 2 {
		be := &oauth2.BearerError{} // no content, just request auth
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), CauseMsg: "malformed Authorization header"}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// TODO - check the audience is the issuer, as we have hardcoded.

	verifier := &jwt.AccessTokenVerifier{
		Provider:       s.oidcProvider,
		IgnoreAudience: true,
	}

	atClaims, err := verifier.VerifyRaw(req.Context(), authSp[1])
	if err != nil {
		slog.ErrorContext(req.Context(), "invalid access token", "error", err)
		be := &oauth2.BearerError{Code: oauth2.BearerErrorCodeInvalidRequest, Description: "invalid access token"}
		herr := &oauth2.HTTPError{Code: http.StatusUnauthorized, WWWAuthenticate: be.String(), Cause: err}
		_ = oauth2.WriteError(w, req, herr)
		return
	}

	// If we make it to here, we have been presented a valid token for a valid session. Run the handler.
	uireq := &UserinfoRequest{
		Subject: atClaims.Subject,
	}

	w.Header().Set("Content-Type", "application/json")

	// TODO - if not set, we should just not handle userinfo.
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

	// TODO - pre-fill the identity parts that use fixed server values.

	if err := json.NewEncoder(w).Encode(uiresp.Identity); err != nil {
		_ = oauth2.WriteError(w, req, err)
		return
	}
}
