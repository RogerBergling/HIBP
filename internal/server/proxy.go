package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// parseTrustedProxyCIDRs validates the source ranges allowed to set
// X-Forwarded-Proto. An empty list is handled by the caller.
func parseTrustedProxyCIDRs(values []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

func loopbackProxyCIDRs() []*net.IPNet {
	_, v4, _ := net.ParseCIDR("127.0.0.0/8")
	_, v6, _ := net.ParseCIDR("::1/128")
	return []*net.IPNet{v4, v6}
}

// proxyAllowed reports whether forwarded headers from this peer may be trusted.
// The demo keeps its previous behavior when no CIDRs are configured; the
// production server defaults to loopback-only in that case.
func (s *Server) proxyAllowed(remoteAddr string) bool {
	if !s.trustProxy {
		return false
	}
	if s.demo != nil && len(s.trustedProxyNets) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, network := range s.trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the originating client address when the direct peer is a
// trusted proxy, otherwise the direct peer address.
func (s *Server) clientIP(r *http.Request) string {
	if s.proxyAllowed(r.RemoteAddr) {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	return clientIP(r)
}
