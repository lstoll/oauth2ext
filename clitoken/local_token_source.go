package clitoken

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oauth2client"
)

// Config configures a CLI local token source. This is used to implement the
// 3-legged oauth2 flow for local/CLI applications, where the callback is a
// dynamic server listening on localhost.
type Config struct {
	// OAuth2Client performs authorization code operations. *oauth2.Config and
	// *clientjwt.Config satisfy this interface.
	OAuth2Client oauth2client.AuthorizationCodeClient
	// ClientType must explicitly identify the public or confidential client.
	ClientType oauth2client.ClientType

	// Opener is used to launch the users browser in to the auth flow. If not
	// set, an appropriate opener for the platform will be automatically
	// configured.
	Opener Opener

	// PortLow is used with PortHigh to specify the port range of the local
	// server. If not set, Go's default port allocation is used. Both PortLow
	// and PortHigh must be specified.
	PortLow uint16
	// PortHigh sets the upper range of ports used to configure the local
	// server, if PortLow is set.
	PortHigh uint16

	// Renderer is used to render the callback page in the users browser, on
	// completion of the auth flow. Defaults to a basic UI
	Renderer Renderer

	// AuthCodeOptions are used to provide additional options to the auth code
	// URL when starting the flow. The code challenge/PKCE option should not be
	// set here, it will be managed dynamically.
	AuthCodeOptions []oauth2.AuthCodeOption
	// SkipPKCE disables the use of PKCE/Code challenge. This should only be
	// used if problems are experienced with it, with consideration to the
	// security implications.
	SkipPKCE bool
}

func (c *Config) getRenderer() Renderer {
	if c.Renderer != nil {
		return c.Renderer
	}
	return &renderer{}
}

func (c *Config) getOpener() Opener {
	if c.Opener != nil {
		return c.Opener
	}
	return DetectOpener()
}

func (c *Config) getPortRange() (low uint16, high uint16) {
	if c.PortLow != 0 && c.PortHigh != 0 {
		return c.PortLow, c.PortHigh
	}
	return 0, 0
}

// TokenSource creates a token source that command line (CLI) programs can use
// to fetch tokens from an OAuth2/OIDC Provider for use in authenticating
// clients to other systems (e.g., Kubernetes clusters, Docker registries,
// etc.). The client should be configured with any scopes or auth code options
// that are required.
//
// This will trigger the auth flow each time, in practice the result should be
// cached. The resulting tokens are not verified, and the caller should verify
// if desired.
//
// Example:
//
//	ctx := context.TODO()
//
//	prov, err := provider.DiscoverOIDCProvider(ctx, issuer)
//	if err != nil {
//	    // handle err
//	}
//
//	cfg := Config{
//	    OAuth2Client: &oauth2.Config{
//	        ClientID:       clientID,
//	        ClientSecret:   clientSecret,
//	        Endpoint:       prov.Endpoint(),
//	        Scopes:         []string{oidc.ScopeOpenID},
//	    },
//	    ClientType: oauth2client.ConfidentialClient,
//	}
//
//	ts, err := cfg.TokenSource(ctx)
//	if err != nil {
//	    // handle err
//	}
//
//	token, err := ts.Token()
//	if err != nil {
//	    // handle error
//	}
//
//	// use token
func (c *Config) TokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &cliTokenSource{ctx: ctx, cfg: c}, nil
}

func (c *Config) validate() error {
	if c == nil {
		return fmt.Errorf("config is required")
	}
	if c.OAuth2Client == nil {
		return fmt.Errorf("OAuth2Client is required")
	}
	if !c.ClientType.Valid() {
		return fmt.Errorf("client type must be explicitly set to public or confidential")
	}
	if c.SkipPKCE && c.ClientType != oauth2client.ConfidentialClient {
		return fmt.Errorf("PKCE can only be disabled for a confidential client")
	}
	return nil
}

type cliTokenSource struct {
	mu  sync.Mutex
	ctx context.Context
	cfg *Config
}

// Token attempts to a fetch a token. The user will be required to open a URL
// in their browser and authenticate to the upstream IdP.
func (c *cliTokenSource) Token() (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.cfg.validate(); err != nil {
		return nil, err
	}

	state := rand.Text()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()

	var calls atomic.Uint32
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		if errMsg := r.FormValue("error"); errMsg != "" {
			err := fmt.Errorf("%s: %s", errMsg, r.FormValue("error_description"))
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error())
			return
		}

		code := r.FormValue("code")
		if code == "" {
			err := fmt.Errorf("no code in request")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error())
			return
		}

		gotState := r.FormValue("state")
		if gotState == "" || gotState != state {
			err := fmt.Errorf("bad state")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error())
			return
		}

		if calls.Add(1) > 1 {
			// Callback has been invoked multiple times, which should not happen.
			// Bomb out to avoid a blocking channel write and to float this as a bug.
			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, "callback invoked multiple times")
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = c.cfg.getRenderer().RenderLocalTokenSourceTokenIssued(w)

		resultCh <- result{code: code}
	})

	if h, ok := c.cfg.getRenderer().(http.Handler); ok {
		mux.Handle("/", h)
	}

	httpSrv := &http.Server{Handler: mux}

	ln, err := newLocalTCPListenerInRange(c.cfg.getPortRange())
	if err != nil {
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}
	defer func() { _ = ln.Close() }()
	tcpAddr := ln.Addr().(*net.TCPAddr)

	go func() { _ = httpSrv.Serve(ln) }()
	defer func() { _ = httpSrv.Shutdown(c.ctx) }()

	var verifier string
	acopts := slices.Clone(c.cfg.AuthCodeOptions)
	if !c.cfg.SkipPKCE {
		verifier = oauth2.GenerateVerifier()
		acopts = append(acopts, oauth2.S256ChallengeOption(verifier))
	}

	// Bind this flow's callback without mutating shared client configuration.
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", tcpAddr.Port)
	acopts = append(acopts, oauth2.SetAuthURLParam("redirect_uri", redirectURL))

	authURL := c.cfg.OAuth2Client.AuthCodeURL(state, acopts...)

	if err := c.cfg.getOpener().Open(c.ctx, authURL); err != nil {
		return nil, fmt.Errorf("failed to open URL: %w", err)
	}

	var res result
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case res = <-resultCh:
		// continue
	}

	if res.err != nil {
		return nil, res.err
	}

	var exchopts []oauth2.AuthCodeOption
	exchopts = append(exchopts, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	if verifier != "" {
		exchopts = append(exchopts, oauth2.VerifierOption(verifier))
	}
	return c.cfg.OAuth2Client.Exchange(c.ctx, res.code, exchopts...)
}

func newLocalTCPListenerInRange(portLow uint16, portHigh uint16) (net.Listener, error) {
	// if 0, 0, we try with :0 which will dynamically allocate
	for i := portLow; i <= portHigh; i++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", i))
		if err == nil {
			return l, nil
		}
	}

	return nil, fmt.Errorf("no TCP port available in the range %d-%d", portLow, portHigh)
}
