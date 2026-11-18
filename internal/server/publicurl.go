package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// parsePublicURL validates the externally visible URL used for LAN mode. An
// empty value keeps the default loopback-only behavior.
func parsePublicURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("public URL must be an absolute URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("public URL must not contain credentials, a query, or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("public URL must not contain a path")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("public URL scheme must be http or https")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return nil, errors.New("public URL must include a host")
	}
	return parsed, nil
}

func isLoopbackHostname(hostname string) bool {
	switch strings.ToLower(strings.Trim(hostname, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

// publicOrigin serializes an URL as a browser origin, omitting default ports.
func publicOrigin(parsed *url.URL) string {
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := parsed.Port()
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		host = net.JoinHostPort(parsed.Hostname(), port)
	}
	return scheme + "://" + host
}

func requestHostname(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
