package middleware

import "strings"

// sanitizeReturnTo validates a post-login redirect target. Only same-origin
// relative paths are allowed: a single leading slash, not a protocol-relative
// URL (//...) or an absolute URL.
func sanitizeReturnTo(returnTo string) string {
	if returnTo == "" {
		return ""
	}
	if !strings.HasPrefix(returnTo, "/") {
		return ""
	}
	if strings.HasPrefix(returnTo, "//") {
		return ""
	}
	if strings.Contains(returnTo, `\`) {
		return ""
	}
	for i := range len(returnTo) {
		// Reject ASCII whitespace and controls. In particular, browsers strip
		// tabs and newlines while parsing URLs, which could turn /<tab>/host
		// into the protocol-relative URL //host after this check.
		if returnTo[i] <= ' ' || returnTo[i] == 0x7f {
			return ""
		}
	}
	return returnTo
}

func resolveReturnTo(returnTo, baseURL string) string {
	if sanitized := sanitizeReturnTo(returnTo); sanitized != "" {
		return sanitized
	}
	if sanitized := sanitizeReturnTo(baseURL); sanitized != "" {
		return sanitized
	}
	return "/"
}
