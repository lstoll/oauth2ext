package middleware

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: ""},
		{name: "root path", input: "/", want: "/"},
		{name: "relative path", input: "/dashboard", want: "/dashboard"},
		{name: "path with query", input: "/search?q=test", want: "/search?q=test"},
		{name: "protocol relative", input: "//evil.com", want: ""},
		{name: "protocol relative with path", input: "//evil.com/phish", want: ""},
		{name: "absolute https", input: "https://evil.com", want: ""},
		{name: "absolute http", input: "http://evil.com", want: ""},
		{name: "no leading slash", input: "dashboard", want: ""},
		{name: "backslash", input: `/\evil.com`, want: ""},
		{name: "embedded tab", input: "/\t/evil.com", want: ""},
		{name: "embedded newline", input: "/ok\n/evil", want: ""},
		{name: "embedded space", input: "/ok /next", want: ""},
		{name: "path with double slash later", input: "/foo//bar", want: "/foo//bar"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeReturnTo(tc.input); got != tc.want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestResolveReturnTo(t *testing.T) {
	tests := []struct {
		name     string
		returnTo string
		baseURL  string
		want     string
	}{
		{name: "uses return to", returnTo: "/home", baseURL: "/fallback", want: "/home"},
		{name: "rejects open redirect", returnTo: "//evil.com", baseURL: "/fallback", want: "/fallback"},
		{name: "rejects absolute base", returnTo: "", baseURL: "https://evil.com", want: "/"},
		{name: "default root", returnTo: "", baseURL: "", want: "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveReturnTo(tc.returnTo, tc.baseURL); got != tc.want {
				t.Errorf("resolveReturnTo(%q, %q) = %q, want %q", tc.returnTo, tc.baseURL, got, tc.want)
			}
		})
	}
}
