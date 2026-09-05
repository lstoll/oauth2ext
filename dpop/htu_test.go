package dpop

import "testing"

func TestNormalizeHTU(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"HTTPS default port": {
			input: "HTTPS://EXAMPLE.COM:443",
			want:  "https://example.com/",
		},
		"HTTP default port with leading zero": {
			input: "http://Example.COM:080/token",
			want:  "http://example.com/token",
		},
		"non-default port": {
			input: "https://Example.COM:8443/token",
			want:  "https://example.com:8443/token",
		},
		"IPv6 default port": {
			input: "https://[2001:DB8::1]:443/token",
			want:  "https://[2001:db8::1]/token",
		},
		"IPv6 zone case remains significant": {
			input: "https://[FE80::A%25En0]:443/token",
			want:  "https://[fe80::a%25En0]/token",
		},
		"percent encoding and dot segments": {
			input: "https://example.com/a/./b/../%7euser/%2f",
			want:  "https://example.com/a/~user/%2F",
		},
		"repeated slashes remain significant": {
			input: "https://example.com/a//b",
			want:  "https://example.com/a//b",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeHTU(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("normalizeHTU(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeHTURejectsInvalidClaims(t *testing.T) {
	for _, input := range []string{
		"/token",
		"https://user@example.com/token",
		"https://example.com/token?query",
		"https://example.com/token#fragment",
		"https://example.com/token%",
		"https://example.com/token%2",
		"https://example.com/token%GG",
		"https://example.com/%",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := normalizeHTU(input); err == nil {
				t.Fatalf("normalizeHTU(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func TestNewValidatorRejectsMalformedExpectedHTU(t *testing.T) {
	for _, htu := range []string{
		"https://example.com/token%",
		"https://example.com/token%2",
		"https://example.com/token%GG",
	} {
		t.Run(htu, func(t *testing.T) {
			if _, err := NewValidator(&ValidatorOpts{
				IgnoreThumbprint: true,
				ExpectedHTU:      &htu,
			}); err == nil {
				t.Fatalf("NewValidator(%q) unexpectedly succeeded", htu)
			}
		})
	}
}
