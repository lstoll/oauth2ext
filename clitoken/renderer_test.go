package clitoken

import (
	"strings"
	"testing"
)

func TestRendererEscapesMessage(t *testing.T) {
	var b strings.Builder
	if err := (&renderer{}).RenderLocalTokenSourceError(&b, `access_denied: <script>alert(1)</script>`); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<script>") {
		t.Fatalf("error message was not escaped:\n%s", out)
	}
	if !strings.Contains(out, "Sign-in failed") || !strings.Contains(out, "access_denied") {
		t.Fatalf("error page missing content:\n%s", out)
	}

	b.Reset()
	if err := (&renderer{}).RenderLocalTokenSourceTokenIssued(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "signed in") {
		t.Fatalf("success page missing content:\n%s", b.String())
	}
}
