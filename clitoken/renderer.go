package clitoken

import (
	"embed"
	"html/template"
	"io"
)

//go:embed templates/*
var templateFS embed.FS

// CSS content
var cssContent string

func init() {
	// Read the CSS file content
	cssBytes, err := templateFS.ReadFile("templates/styles.css")
	if err != nil {
		panic(err)
	}
	cssContent = string(cssBytes)
}

// Templates
var (
	tmplError       = template.Must(template.ParseFS(templateFS, "templates/error.html"))
	tmplTokenIssued = template.Must(template.ParseFS(templateFS, "templates/success.html"))
)

type Renderer interface {
	RenderLocalTokenSourceTokenIssued(w io.Writer) error
	RenderLocalTokenSourceError(w io.Writer, message string) error
}

type renderer struct{}

// RenderLocalTokenSourceTokenIssued renders a success message after issuing a token.
func (r *renderer) RenderLocalTokenSourceTokenIssued(w io.Writer) error {
	data := struct {
		CSS template.CSS
	}{
		CSS: template.CSS(cssContent),
	}
	return tmplTokenIssued.Execute(w, data)
}

// RenderLocalTokenSourceError renders an unrecoverable error.
func (r *renderer) RenderLocalTokenSourceError(w io.Writer, message string) error {
	data := struct {
		CSS     template.CSS
		Message string
	}{
		CSS:     template.CSS(cssContent),
		Message: message,
	}
	return tmplError.Execute(w, data)
}
