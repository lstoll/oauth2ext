package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
)

func TestCookiestore_SaveGetOIDCSession(t *testing.T) {
	store := &Cookiestore{}

	now := time.Now()
	token := &oauth2.Token{
		AccessToken: "test-access-token",
		Expiry:      now.Add(1 * time.Hour),
	}
	token = oidc.AddIDToken(token, newTestIDToken(map[string]any{"exp": time.Now().Add(1 * time.Hour).Unix()}))

	savedSessionData := &SessionData{
		Token: &oidc.TokenWithID{Token: token},
		Logins: []SessionDataLogin{
			{State: "state1", PKCEChallenge: "challenge1", ReturnTo: "/return1", Expires: int(now.Add(10 * time.Minute).Unix())},
			{State: "state2", PKCEChallenge: "challenge2", ReturnTo: "/return2", Expires: int(now.Add(20 * time.Minute).Unix())},
			// will be dropped as it's expired
			{State: "state3", Expires: int(now.Add(-10 * time.Minute).Unix())},
		},
	}
	expectedSessionData := &SessionData{
		Token: &oidc.TokenWithID{Token: token},
		Logins: []SessionDataLogin{
			{State: "state1", PKCEChallenge: "challenge1", ReturnTo: "/return1", Expires: int(now.Add(10 * time.Minute).Unix())},
			{State: "state2", PKCEChallenge: "challenge2", ReturnTo: "/return2", Expires: int(now.Add(20 * time.Minute).Unix())},
		},
	}

	rr := httptest.NewRecorder()
	err := store.SaveOIDCSession(rr, httptest.NewRequest("GET", "/", nil), savedSessionData)
	if err != nil {
		t.Fatalf("SaveOIDCSession failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	retrievedSessionData, err := store.GetOIDCSession(req)
	if err != nil {
		t.Fatalf("GetOIDCSession failed: %v", err)
	}

	if diff := cmp.Diff(expectedSessionData, retrievedSessionData,
		cmpopts.IgnoreUnexported(oauth2.Token{}),
		cmpopts.SortSlices(func(a, b SessionDataLogin) bool { // match our sort
			return a.Expires < b.Expires
		}),
		cmpopts.IgnoreFields(oauth2.Token{}, "AccessToken"), // we intentionally strip this out
		cmpopts.IgnoreFields(oauth2.Token{}, "Expiry"),      // also stripped, and not used in the middleware
	); diff != "" {
		t.Errorf("Session data mismatch (-want +got):\n%s", diff)
	}

	// create a new request with the same cookies, but save empty session data
	// to it. This should clear all items.
	delRR := httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}
	err = store.SaveOIDCSession(delRR, req, &SessionData{})
	if err != nil {
		t.Fatalf("SaveOIDCSession failed: %v", err)
	}

	if len(delRR.Result().Cookies()) != 3 {
		// the token, and two login states
		t.Errorf("expected 3 cookies for deletion, got %d", len(delRR.Result().Cookies()))
	}

	for _, cookie := range delRR.Result().Cookies() {
		// every written cookie should be marked to remove, on the go side
		// that's a negative max age. Go maps this back to 0.
		if cookie.MaxAge >= 0 {
			t.Errorf("cookie %q should have been removed, but it's still present", cookie.Name)
		}
	}
}

func newTestIDToken(claims map[string]any) string {
	// For testing, we only need the payload part for peekIDT to extract expiry

	if claims == nil {
		claims = make(map[string]any)
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix() // Default expiry
	}

	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
	return header + "." + payload + "." + "signature"
}

func TestCookiestore_GetOIDCSession_NoCookies(t *testing.T) {
	store := &Cookiestore{CookieOpts: &DefaultCookieOpts}
	req := httptest.NewRequest("GET", "/", nil)

	sd, err := store.GetOIDCSession(req)
	if err != nil {
		t.Fatalf("GetOIDCSession failed: %v", err)
	}
	if sd.Token != nil {
		t.Errorf("Expected no token, got %v", sd.Token)
	}
	if len(sd.Logins) != 0 {
		t.Errorf("Expected no logins, got %v", sd.Logins)
	}
}
