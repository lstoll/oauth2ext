package clitoken

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sync"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

type RenderOpts struct {
	// CloseAfter is the duration to wait before closing the browser window. If
	// not set, the browser window will not be closed automatically.
	CloseAfter time.Duration
}

type Renderer interface {
	RenderLocalTokenSourceTokenIssued(w io.Writer, opts *RenderOpts) error
	RenderLocalTokenSourceError(w io.Writer, message string, opts *RenderOpts) error
}

type renderer struct {
	initOnce sync.Once

	cssContent      []byte
	tmplError       *template.Template
	tmplTokenIssued *template.Template
}

// RenderLocalTokenSourceTokenIssued renders a success message after issuing a token.
func (r *renderer) RenderLocalTokenSourceTokenIssued(w io.Writer, opts *RenderOpts) error {
	if err := r.init(); err != nil {
		return fmt.Errorf("failed to initialize renderer: %w", err)
	}
	var closeAfterMs int64
	if opts != nil && opts.CloseAfter > 0 {
		closeAfterMs = int64(opts.CloseAfter / time.Millisecond)
	}
	data := struct {
		CSS        template.CSS
		CloseAfter int64 // milliseconds; 0 means do not auto-close
	}{
		CSS:        template.CSS(r.cssContent),
		CloseAfter: closeAfterMs,
	}
	return r.tmplTokenIssued.Execute(w, data)
}

// RenderLocalTokenSourceError renders an unrecoverable error.
func (r *renderer) RenderLocalTokenSourceError(w io.Writer, message string, opts *RenderOpts) error {
	if err := r.init(); err != nil {
		return fmt.Errorf("failed to initialize renderer: %w", err)
	}
	var closeAfterMs int64
	if opts != nil && opts.CloseAfter > 0 {
		closeAfterMs = int64(opts.CloseAfter / time.Millisecond)
	}
	data := struct {
		CSS        template.CSS
		Message    string
		CloseAfter int64 // milliseconds; 0 means do not auto-close
	}{
		CSS:        template.CSS(r.cssContent),
		Message:    message,
		CloseAfter: closeAfterMs,
	}
	return r.tmplError.Execute(w, data)
}

func (r *renderer) init() error {
	var err error
	r.initOnce.Do(func() {
		r.cssContent, err = templateFS.ReadFile("templates/styles.css")
		if err != nil {
			return
		}
		r.tmplError, err = template.ParseFS(templateFS, "templates/error.html")
		if err != nil {
			return
		}
		r.tmplTokenIssued, err = template.ParseFS(templateFS, "templates/success.html")
	})
	return err
}
