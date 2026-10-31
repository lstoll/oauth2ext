package dpop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"lds.li/oauth2ext/jwt"
)

// maxNonceErrorBody bounds how much of a 400 response is read when checking
// for a use_dpop_nonce error.
const maxNonceErrorBody = 64 << 10

// Transport is an [http.RoundTripper] that adds DPoP headers to requests.
//
// It handles server-provided nonces (RFC 9449 sections 8 and 9): the latest
// DPoP-Nonce from each origin is included in later proofs, and a request
// rejected with use_dpop_nonce is retried once with the new nonce. Requests
// with a body are only retried if it can be replayed via Request.GetBody.
// Reuse a Transport to avoid the extra round trip on each request.
type Transport struct {
	// Signer is used to sign DPoP proofs.
	Signer *jwt.SigningIdentity
	// IncludeCertificates opts into including the signer's configured x5c chain
	// in each proof. Certificate chains can disclose organization or host
	// identity to every DPoP recipient.
	IncludeCertificates bool

	// Base is the underlying transport. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	mu     sync.Mutex
	nonces map[string]string // by origin
}

// RoundTrip implements [http.RoundTripper] by adding a DPoP header to the
// request and then calling the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Signer == nil {
		closeBody(req)
		return nil, fmt.Errorf("dpop: Signer is nil")
	}

	origin := strings.ToLower(req.URL.Scheme + "://" + req.URL.Host)
	sent := t.nonce(origin)
	resp, err := t.send(req, sent)
	if err != nil {
		return nil, err
	}

	issued := resp.Header.Get("DPoP-Nonce")
	if issued == "" {
		return resp, nil
	}
	t.setNonce(origin, issued)
	if issued == sent || !replayable(req) {
		return resp, nil
	}
	if !requiresNonce(resp) {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNonceErrorBody))
	_ = resp.Body.Close()

	retryReq := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("dpop: replaying request body: %w", err)
		}
		retryReq.Body = body
	}
	resp, err = t.send(retryReq, issued)
	if err != nil {
		return nil, err
	}
	// Remember a nonce rotated on the retry, without retrying again.
	if next := resp.Header.Get("DPoP-Nonce"); next != "" {
		t.setNonce(origin, next)
	}
	return resp, nil
}

func (t *Transport) send(req *http.Request, nonce string) (*http.Response, error) {
	proofURL := *req.URL
	proofURL.RawQuery = ""
	proofURL.ForceQuery = false
	proofURL.Fragment = ""
	options := ProofOptions{
		HTTPMethod:          req.Method,
		HTTPURI:             proofURL.String(),
		Nonce:               nonce,
		IncludeCertificates: t.IncludeCertificates,
	}
	if scheme, token, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "DPoP") {
		options.AccessToken = token
	}
	proof, err := Sign(req.Context(), t.Signer, options)
	if err != nil {
		closeBody(req)
		return nil, fmt.Errorf("dpop: failed to create proof: %w", err)
	}

	// Clone the request to avoid modifying the original
	req = req.Clone(req.Context())
	req.Header.Set("DPoP", proof)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func (t *Transport) nonce(origin string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonces[origin]
}

func (t *Transport) setNonce(origin, nonce string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nonces == nil {
		t.nonces = make(map[string]string)
	}
	t.nonces[origin] = nonce
}

// requiresNonce reports whether resp rejected the request with
// use_dpop_nonce. Resource servers signal this with a 401 DPoP challenge, and
// authorization servers with a 400 JSON error. A 400 body is restored after
// it is inspected.
func requiresNonce(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		for _, value := range resp.Header.Values("WWW-Authenticate") {
			if dpopChallengeError(value) == "use_dpop_nonce" {
				return true
			}
		}
	case http.StatusBadRequest:
		if resp.Body == nil {
			return false
		}
		head, err := io.ReadAll(io.LimitReader(resp.Body, maxNonceErrorBody))
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		if err != nil {
			return false // the caller sees the read error
		}
		var body struct {
			Error string `json:"error"`
		}
		return json.Unmarshal(head, &body) == nil && body.Error == "use_dpop_nonce"
	}
	return false
}

func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// dpopChallengeError returns the error parameter of the DPoP challenge in a
// WWW-Authenticate value, which may hold several challenges (RFC 9110 section
// 11.6.1). Parameters may have whitespace around "=" and quoted values (RFC
// 9110 section 11.2). It returns "" if there is no DPoP challenge or error.
func dpopChallengeError(value string) string {
	p := challengeParser{s: value}
	inDPoP := false
	for {
		p.skip(" \t,")
		if p.done() {
			return ""
		}
		tok := p.token()
		if tok == "" {
			return "" // malformed
		}
		p.skip(" \t")
		if p.peek() != '=' {
			// A token not followed by "=" starts a new challenge.
			inDPoP = strings.EqualFold(tok, "DPoP")
			continue
		}
		p.pos++
		p.skip(" \t")
		if c := p.peek(); c == 0 || c == ',' || c == '=' {
			// token68 padding, e.g. "Basic dXNlcg==".
			p.skip("=")
			continue
		}
		var val string
		if p.peek() == '"' {
			val = p.quoted()
		} else {
			val = p.token()
		}
		if inDPoP && strings.EqualFold(tok, "error") {
			return val
		}
	}
}

type challengeParser struct {
	s   string
	pos int
}

func (p *challengeParser) done() bool { return p.pos >= len(p.s) }

func (p *challengeParser) peek() byte {
	if p.done() {
		return 0
	}
	return p.s[p.pos]
}

func (p *challengeParser) skip(chars string) {
	for !p.done() && strings.IndexByte(chars, p.s[p.pos]) >= 0 {
		p.pos++
	}
}

// token reads an RFC 9110 token, also accepting "/" for token68 values.
func (p *challengeParser) token() string {
	start := p.pos
	for !p.done() {
		c := p.s[p.pos]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~/", c) >= 0 {
			p.pos++
			continue
		}
		break
	}
	return p.s[start:p.pos]
}

// quoted reads a quoted-string starting at the opening quote, unescaping it.
func (p *challengeParser) quoted() string {
	p.pos++ // opening quote
	var b strings.Builder
	for !p.done() {
		c := p.s[p.pos]
		p.pos++
		switch {
		case c == '"':
			return b.String()
		case c == '\\' && !p.done():
			b.WriteByte(p.s[p.pos])
			p.pos++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
