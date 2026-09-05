package dpop

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizeHTU applies the syntax- and scheme-based URI normalization that
// RFC 9449 recommends before comparing DPoP htu claims. Query and fragment
// components are rejected because an htu claim must not contain them.
func normalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("must be an absolute hierarchical URI with an authority")
	}
	if u.User != nil {
		return "", fmt.Errorf("must not contain user information")
	}
	if u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return "", fmt.Errorf("must not contain query or fragment components")
	}

	u.Scheme = strings.ToLower(u.Scheme)
	bracketedHost := strings.HasPrefix(u.Host, "[")
	hostname := u.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("must contain a host")
	}
	if bracketedHost {
		address, zone, hasZone := strings.Cut(hostname, "%")
		hostname = strings.ToLower(address)
		if hasZone {
			hostname += "%" + zone
		}
	} else {
		hostname = strings.ToLower(hostname)
	}
	port := normalizePort(u.Port())
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if bracketedHost {
		u.Host = "[" + hostname + "]"
	} else {
		u.Host = hostname
	}
	if port != "" {
		u.Host += ":" + port
	}

	escapedPath := u.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	escapedPath, err = normalizePercentEncoding(escapedPath)
	if err != nil {
		return "", err
	}
	escapedPath = removeDotSegments(escapedPath)
	path, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", err
	}
	u.Path = path
	u.RawPath = escapedPath

	return u.String(), nil
}

func normalizePort(port string) string {
	if port == "" {
		return ""
	}
	port = strings.TrimLeft(port, "0")
	if port == "" {
		return "0"
	}
	return port
}

func normalizePercentEncoding(s string) (string, error) {
	var out strings.Builder
	out.Grow(len(s))
	const upperHex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("invalid percent-encoding")
		}
		hi, ok := unhex(s[i+1])
		if !ok {
			return "", fmt.Errorf("invalid percent-encoding")
		}
		lo, ok := unhex(s[i+2])
		if !ok {
			return "", fmt.Errorf("invalid percent-encoding")
		}
		value := hi<<4 | lo
		if isUnreserved(value) {
			out.WriteByte(value)
		} else {
			out.WriteByte('%')
			out.WriteByte(upperHex[value>>4])
			out.WriteByte(upperHex[value&0xf])
		}
		i += 2
	}
	return out.String(), nil
}

func unhex(b byte) (byte, bool) {
	switch {
	case '0' <= b && b <= '9':
		return b - '0', true
	case 'a' <= b && b <= 'f':
		return b - 'a' + 10, true
	case 'A' <= b && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func isUnreserved(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~'
}

// removeDotSegments implements the algorithm in RFC 3986 section 5.2.4
// without collapsing repeated slashes, which can be path-significant.
func removeDotSegments(input string) string {
	var output string
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output = removeLastSegment(output)
		case input == "/..":
			input = "/"
			output = removeLastSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			end := strings.IndexByte(input[1:], '/')
			if end < 0 {
				output += input
				input = ""
			} else {
				end++
				output += input[:end]
				input = input[end:]
			}
		}
	}
	return output
}

func removeLastSegment(path string) string {
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		return path[:slash]
	}
	return ""
}
