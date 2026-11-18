package server

import "testing"

func TestParsePublicURL(t *testing.T) {
	if parsed, err := parsePublicURL(""); err != nil || parsed != nil {
		t.Fatalf("empty URL: parsed=%v err=%v", parsed, err)
	}
	parsed, err := parsePublicURL("https://hibp.lan:8443/")
	if err != nil || parsed.Hostname() != "hibp.lan" || parsed.Port() != "8443" {
		t.Fatalf("valid URL: parsed=%v err=%v", parsed, err)
	}
	for _, raw := range []string{
		"hibp.lan:8443",
		"https://hibp.lan:8443/path",
		"https://hibp.lan:8443?x=1",
		"https://hibp.lan:8443#fragment",
		"https://user:pass@hibp.lan:8443",
		"ftp://hibp.lan:8443",
	} {
		if _, err := parsePublicURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestPublicOriginOmitsDefaultPorts(t *testing.T) {
	tests := map[string]string{
		"https://hibp.lan:8443": "https://hibp.lan:8443",
		"https://hibp.lan:443":  "https://hibp.lan",
		"https://hibp.lan":      "https://hibp.lan",
		"http://localhost:80":   "http://localhost",
		"http://localhost:8080": "http://localhost:8080",
	}
	for raw, want := range tests {
		parsed, err := parsePublicURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := publicOrigin(parsed); got != want {
			t.Fatalf("%s: got %q, want %q", raw, got, want)
		}
	}
}
