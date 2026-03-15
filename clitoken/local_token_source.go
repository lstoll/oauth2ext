package clitoken

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

// Config configures a CLI local token source. This is used to implement the
// 3-legged oauth2 flow for local/CLI applications, where the callback is a
// dynamic server listening on localhost.
type Config struct {
	// OAuth2Config is the configuration for the provider. Required.
	OAuth2Config oauth2.Config

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
//	provider, err := oidc.DiscoverProvider(ctx, issuer)
//	if err != nil {
//	    // handle err
//	}
//
//	cfg := Config{
//	    OAuth2Config: oauth2.Config{
//	        ClientID:       clientID,
//	        ClientSecret:   clientSecret,
//	        Endpoint:       provider.Endpoint(),
//	        Scopes:         []string{oidc.ScopeOpenID},
//	    }
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
	return &cliTokenSource{ctx: ctx, cfg: c}, nil
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

	// shallow clone, as we mutate it
	o2cfg := c.cfg.OAuth2Config

	state := rand.Text()

	type result struct {
		code string
		err  error
	}
	resultCh := make(chan result, 1)

	mux := http.NewServeMux()

	var calls atomic.Uint32
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		renderOpts := &RenderOpts{}

		if returner, ok := c.cfg.getOpener().(OpenerReturner); ok && returner.CanReturn() {
			renderOpts.CloseAfter = time.Second * 2
		}

		if errMsg := r.FormValue("error"); errMsg != "" {
			err := fmt.Errorf("%s: %s", errMsg, r.FormValue("error_description"))
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error(), renderOpts)
			return
		}

		code := r.FormValue("code")

		if code == "" {
			err := fmt.Errorf("no code in request")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error(), renderOpts)
			return
		}

		gotState := r.FormValue("state")
		if gotState == "" || gotState != state {
			err := fmt.Errorf("bad state")
			resultCh <- result{err: err}

			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, err.Error(), renderOpts)
			return
		}

		if calls.Add(1) > 1 {
			// Callback has been invoked multiple times, which should not happen.
			// Bomb out to avoid a blocking channel write and to float this as a bug.
			w.WriteHeader(http.StatusBadRequest)
			_ = c.cfg.getRenderer().RenderLocalTokenSourceError(w, "callback invoked multiple times", renderOpts)
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = c.cfg.getRenderer().RenderLocalTokenSourceTokenIssued(w, renderOpts)

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

	var (
		verifier string
		acopts   []oauth2.AuthCodeOption
	)
	if !c.cfg.SkipPKCE {
		verifier = oauth2.GenerateVerifier()
		acopts = append(c.cfg.AuthCodeOptions, oauth2.S256ChallengeOption(verifier))
	}

	// we need to update this each invocation
	o2cfg.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", tcpAddr.Port)

	authURL := o2cfg.AuthCodeURL(state, acopts...)

	if err := c.cfg.getOpener().Open(c.ctx, authURL); err != nil {
		return nil, fmt.Errorf("failed to open URL: %w", err)
	}

	var res result
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case res = <-resultCh:
		// continue, returning if needed
		if returner, ok := c.cfg.getOpener().(OpenerReturner); ok && returner.CanReturn() {
			if err := returner.Return(c.ctx); err != nil {
				return nil, fmt.Errorf("failed to return to calling application: %w", err)
			}
		}
	}

	if res.err != nil {
		return nil, res.err
	}

	var exchopts []oauth2.AuthCodeOption
	if verifier != "" {
		exchopts = append(exchopts, oauth2.VerifierOption(verifier))
	}
	return o2cfg.Exchange(c.ctx, res.code, exchopts...)
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
