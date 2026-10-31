package dpop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nonceServer requires proofs to carry its current nonce, rejecting others
// the way a resource server (401) or authorization server (400) does.
type nonceServer struct {
	t      *testing.T
	nonce  string
	rotate bool // reject every request, issuing a new nonce each time
	as     bool
	nonces []string
	bodies []string
}

func (s *nonceServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	validator, err := NewValidator(&ValidatorOpts{IgnoreThumbprint: true})
	if err != nil {
		s.t.Fatal(err)
	}
	proof, err := (&Verifier{}).VerifyAndDecode(r.Header.Get("DPoP"), validator)
	if err != nil {
		s.t.Errorf("proof: %v", err)
		http.Error(w, "bad proof", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	s.nonces = append(s.nonces, proof.Nonce)
	s.bodies = append(s.bodies, string(body))
	if s.rotate || proof.Nonce != s.nonce {
		if s.rotate {
			s.nonce = s.nonce + "x"
		}
		w.Header().Set("DPoP-Nonce", s.nonce)
		if s.as {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"use_dpop_nonce","error_description":"nonce required"}`)
			return
		}
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _ = io.WriteString(w, "ok")
}

func doNonceRequest(t *testing.T, transport *Transport, method, url string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func TestTransportResourceServerNonce(t *testing.T) {
	srv := &nonceServer{t: t, nonce: "n1"}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}

	if code, body := doNonceRequest(t, transport, http.MethodGet, ts.URL, nil); code != http.StatusOK || body != "ok" {
		t.Fatalf("got %d %q", code, body)
	}
	if want := []string{"", "n1"}; strings.Join(srv.nonces, ",") != strings.Join(want, ",") {
		t.Fatalf("proof nonces %q, want %q", srv.nonces, want)
	}

	// The nonce is remembered for later requests to the same origin.
	if code, _ := doNonceRequest(t, transport, http.MethodGet, ts.URL+"/other", nil); code != http.StatusOK {
		t.Fatalf("second request got %d", code)
	}
	if len(srv.nonces) != 3 || srv.nonces[2] != "n1" {
		t.Fatalf("second request proof nonces %q", srv.nonces)
	}
}

func TestTransportAuthorizationServerNonceReplaysBody(t *testing.T) {
	srv := &nonceServer{t: t, nonce: "n1", as: true}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}

	const form = "grant_type=refresh_token&refresh_token=abc"
	if code, body := doNonceRequest(t, transport, http.MethodPost, ts.URL+"/token", strings.NewReader(form)); code != http.StatusOK || body != "ok" {
		t.Fatalf("got %d %q", code, body)
	}
	if len(srv.bodies) != 2 || srv.bodies[0] != form || srv.bodies[1] != form {
		t.Fatalf("request bodies %q, want the form twice", srv.bodies)
	}
}

func TestTransportNonceRetriesOnce(t *testing.T) {
	srv := &nonceServer{t: t, nonce: "n", rotate: true}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}

	if code, _ := doNonceRequest(t, transport, http.MethodGet, ts.URL, nil); code != http.StatusUnauthorized {
		t.Fatalf("got %d, want the second rejection", code)
	}
	if len(srv.nonces) != 2 {
		t.Fatalf("made %d requests, want 2", len(srv.nonces))
	}
}

func TestTransportNonceWithoutReplayableBody(t *testing.T) {
	srv := &nonceServer{t: t, nonce: "n1", as: true}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}

	// io.MultiReader hides the body type, so http.NewRequest can't set GetBody.
	code, body := doNonceRequest(t, transport, http.MethodPost, ts.URL, io.MultiReader(strings.NewReader("data")))
	if code != http.StatusBadRequest || !strings.Contains(body, "use_dpop_nonce") {
		t.Fatalf("got %d %q, want the original rejection with its body", code, body)
	}
	if len(srv.nonces) != 1 {
		t.Fatalf("made %d requests, want 1", len(srv.nonces))
	}
}

func TestTransportOtherBadRequestKeepsBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "n1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}

	code, body := doNonceRequest(t, transport, http.MethodPost, ts.URL, strings.NewReader("x"))
	if code != http.StatusBadRequest || body != `{"error":"invalid_grant"}` {
		t.Fatalf("got %d %q", code, body)
	}
}

func TestDPoPChallengeError(t *testing.T) {
	for value, want := range map[string]string{
		`DPoP error="use_dpop_nonce"`:                                   "use_dpop_nonce",
		`DPoP error = "use_dpop_nonce"`:                                 "use_dpop_nonce",
		`dpop error=use_dpop_nonce`:                                     "use_dpop_nonce",
		`Bearer realm="api", DPoP error="use_dpop_nonce"`:               "use_dpop_nonce",
		`Basic dXNlcg==, DPoP algs="ES256", error="use_dpop_nonce"`:     "use_dpop_nonce",
		`DPoP realm="a, error=\"x\"", error="invalid_token"`:            "invalid_token",
		`Bearer error="use_dpop_nonce"`:                                 "",
		`DPoP error="invalid_token", Bearer realm="api"`:                "invalid_token",
		`DPoP algs="ES256"`:                                             "",
		`Bearer realm="api", error="use_dpop_nonce", DPoP algs="ES256"`: "",
		``:        "",
		`"broken`: "",
	} {
		if got := dpopChallengeError(value); got != want {
			t.Errorf("dpopChallengeError(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestTransportCombinedChallengeNonce(t *testing.T) {
	for _, challenge := range []string{
		`Bearer realm="api", DPoP error="use_dpop_nonce"`,
		`DPoP error = "use_dpop_nonce"`,
	} {
		t.Run(challenge, func(t *testing.T) {
			hits := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if proofNonce(t, r) != "n1" {
					w.Header().Set("DPoP-Nonce", "n1")
					w.Header().Set("WWW-Authenticate", challenge)
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			t.Cleanup(ts.Close)
			transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}
			if code, _ := doNonceRequest(t, transport, http.MethodGet, ts.URL, nil); code != http.StatusOK || hits != 2 {
				t.Fatalf("got %d after %d requests, want 200 after 2", code, hits)
			}
		})
	}
}

func TestTransportRemembersNonceFromRetryResponse(t *testing.T) {
	var seen []string
	expected := "n1"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := proofNonce(t, r)
		seen = append(seen, got)
		if got != expected {
			w.Header().Set("DPoP-Nonce", expected)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Successful responses can rotate the nonce for the next request.
		expected = "n2"
		w.Header().Set("DPoP-Nonce", expected)
	}))
	t.Cleanup(ts.Close)
	transport := &Transport{Signer: mustSigner(t, generateTestKey(t))}
	for range 2 {
		if code, _ := doNonceRequest(t, transport, http.MethodGet, ts.URL, nil); code != http.StatusOK {
			t.Fatalf("got %d", code)
		}
	}
	if strings.Join(seen, ",") != ",n1,n2" {
		t.Fatalf("proof nonces %q, want [\"\" n1 n2]", seen)
	}
}

func proofNonce(t *testing.T, r *http.Request) string {
	t.Helper()
	validator, err := NewValidator(&ValidatorOpts{IgnoreThumbprint: true})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := (&Verifier{}).VerifyAndDecode(r.Header.Get("DPoP"), validator)
	if err != nil {
		t.Errorf("proof: %v", err)
		return "invalid"
	}
	return proof.Nonce
}
