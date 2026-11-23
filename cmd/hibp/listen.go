package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// serverListenConfig is the validated listener policy. A non-loopback
// listener is only allowed with TLS, or with an explicitly trusted TLS
// terminating proxy and a public HTTPS URL.
type serverListenConfig struct {
	TLS               bool
	TrustProxy        bool
	TrustedProxyCIDRs []string
	PublicURL         string
}

func validateServerListen(listen, tlsCert, tlsKey, publicURL string, trustProxy bool, trustedProxyCIDRs string) (serverListenConfig, error) {
	listen = strings.TrimSpace(listen)
	tlsCert = strings.TrimSpace(tlsCert)
	tlsKey = strings.TrimSpace(tlsKey)
	publicURL = strings.TrimSpace(publicURL)
	trustedProxyCIDRs = strings.TrimSpace(trustedProxyCIDRs)

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return serverListenConfig{}, fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return serverListenConfig{}, errors.New("listen address must include a host, for example 127.0.0.1:8443 or 192.168.1.10:8443")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return serverListenConfig{}, errors.New("listen port must be between 1 and 65535")
	}
	loopback := isLoopbackListenHost(host)
	tlsEnabled := tlsCert != "" || tlsKey != ""
	if (tlsCert == "") != (tlsKey == "") {
		return serverListenConfig{}, errors.New("--tls-cert and --tls-key must be set together")
	}
	if tlsEnabled && trustProxy {
		return serverListenConfig{}, errors.New("choose either built-in TLS (--tls-cert/--tls-key) or --trust-proxy, not both")
	}
	if tlsEnabled {
		if _, err := tls.LoadX509KeyPair(tlsCert, tlsKey); err != nil {
			return serverListenConfig{}, fmt.Errorf("load TLS certificate: %w", err)
		}
	}
	if !loopback && !tlsEnabled && !trustProxy {
		return serverListenConfig{}, fmt.Errorf("refusing to listen on %q without TLS; set --tls-cert and --tls-key, keep the listener on 127.0.0.1/localhost and use an SSH tunnel, or configure --trust-proxy with --public-url and --trusted-proxy-cidrs", listen)
	}
	if trustProxy && publicURL == "" {
		return serverListenConfig{}, errors.New("--public-url is required with --trust-proxy, for example https://hibp.example.com")
	}
	if !loopback && publicURL == "" {
		return serverListenConfig{}, errors.New("--public-url is required for a LAN listener, for example --public-url https://hibp.example.com")
	}
	cidrs := splitList(trustedProxyCIDRs)
	if trustProxy {
		for _, cidr := range cidrs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return serverListenConfig{}, fmt.Errorf("invalid --trusted-proxy-cidrs entry %q: %w", cidr, err)
			}
		}
		if !loopback && len(cidrs) == 0 {
			return serverListenConfig{}, errors.New("a non-loopback --trust-proxy listener requires --trusted-proxy-cidrs, for example 127.0.0.1/32 or the proxy's private subnet")
		}
	}
	if publicURL == "" {
		if tlsEnabled && loopback {
			publicURL = "https://localhost:" + port
		}
	} else {
		parsed, err := url.Parse(publicURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return serverListenConfig{}, errors.New("--public-url must be an absolute URL, for example https://hibp.example.com")
		}
		if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return serverListenConfig{}, errors.New("--public-url must not contain credentials, a query, or a fragment")
		}
		if parsed.Path != "" && parsed.Path != "/" {
			return serverListenConfig{}, errors.New("--public-url must not contain a path; HIBP is served at the root")
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return serverListenConfig{}, errors.New("--public-url scheme must be http or https")
		}
		publicHost := strings.ToLower(parsed.Hostname())
		if publicHost == "" {
			return serverListenConfig{}, errors.New("--public-url must include a host")
		}
		if trustProxy {
			if scheme != "https" {
				return serverListenConfig{}, errors.New("--public-url must use https when --trust-proxy is enabled")
			}
		} else {
			if scheme == "http" && !isLoopbackListenHost(publicHost) {
				return serverListenConfig{}, errors.New("a non-loopback --public-url must use https")
			}
			if tlsEnabled && scheme != "https" {
				return serverListenConfig{}, errors.New("--public-url must use https when TLS is enabled")
			}
			if !tlsEnabled && scheme == "https" {
				return serverListenConfig{}, errors.New("--public-url uses https but TLS is not enabled; use --trust-proxy or configure --tls-cert/--tls-key")
			}
			if isLoopbackListenHost(publicHost) != loopback {
				return serverListenConfig{}, errors.New("--public-url host and --listen address must both be loopback or both be network-visible")
			}
			publicPort := parsed.Port()
			if publicPort == "" {
				if scheme == "https" {
					publicPort = "443"
				} else {
					publicPort = "80"
				}
			}
			if publicPort != port {
				return serverListenConfig{}, fmt.Errorf("--public-url port %s must match the listen port %s", publicPort, port)
			}
		}
		publicURL = normalizePublicURL(scheme, parsed)
	}
	return serverListenConfig{
		TLS:               tlsEnabled,
		TrustProxy:        trustProxy,
		TrustedProxyCIDRs: cidrs,
		PublicURL:         publicURL,
	}, nil
}

func normalizePublicURL(scheme string, parsed *url.URL) string {
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := parsed.Port()
	defaultPort := (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
	if port != "" && !defaultPort {
		host = net.JoinHostPort(parsed.Hostname(), port)
	}
	return scheme + "://" + host
}

func isLoopbackListenHost(host string) bool {
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}
