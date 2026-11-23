package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateServerListen(t *testing.T) {
	cert, key := testTLSKeyPair(t)
	tests := []struct {
		name         string
		listen       string
		cert         string
		key          string
		publicURL    string
		trustProxy   bool
		trustedCIDRs string
		wantTLS      bool
		wantURL      string
		wantErr      bool
	}{
		{name: "default loopback", listen: "127.0.0.1:8443"},
		{name: "localhost loopback", listen: "localhost:8443"},
		{name: "LAN without TLS", listen: "192.168.1.10:8443", wantErr: true},
		{name: "LAN TLS without public URL", listen: "192.168.1.10:8443", cert: cert, key: key, wantErr: true},
		{name: "LAN plain HTTP public URL", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "http://hibp.lan:8443", wantErr: true},
		{name: "LAN port mismatch", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://hibp.lan:9443", wantErr: true},
		{name: "LAN TLS", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443", wantTLS: true, wantURL: "https://hibp.lan:8443"},
		{name: "all interfaces TLS", listen: "0.0.0.0:8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443", wantTLS: true, wantURL: "https://hibp.lan:8443"},
		{name: "LAN IP public URL", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://192.168.1.10:8443", wantTLS: true, wantURL: "https://192.168.1.10:8443"},
		{name: "loopback with LAN URL", listen: "127.0.0.1:8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443", wantErr: true},
		{name: "loopback TLS default URL", listen: "127.0.0.1:8443", cert: cert, key: key, wantTLS: true, wantURL: "https://localhost:8443"},
		{name: "loopback HTTP URL", listen: "127.0.0.1:8443", publicURL: "http://localhost:8443", wantURL: "http://localhost:8443"},
		{name: "loopback HTTPS without TLS", listen: "127.0.0.1:8443", publicURL: "https://localhost:8443", wantErr: true},
		{name: "empty listen host", listen: ":8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443", wantErr: true},
		{name: "path in public URL", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443/path", wantErr: true},
		{name: "query in public URL", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://hibp.lan:8443?x=1", wantErr: true},
		{name: "credentials in public URL", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://user@hibp.lan:8443", wantErr: true},
		{name: "default HTTPS port", listen: "192.168.1.10:443", cert: cert, key: key, publicURL: "https://hibp.lan", wantTLS: true, wantURL: "https://hibp.lan"},
		{name: "explicit default HTTPS port", listen: "192.168.1.10:443", cert: cert, key: key, publicURL: "https://hibp.lan:443", wantTLS: true, wantURL: "https://hibp.lan"},

		{name: "proxy loopback listener", listen: "127.0.0.1:8443", publicURL: "https://hibp.lan", trustProxy: true, wantURL: "https://hibp.lan"},
		{name: "proxy non-loopback without CIDRs", listen: "0.0.0.0:8017", publicURL: "https://hibp.lan", trustProxy: true, wantErr: true},
		{name: "proxy non-loopback with CIDR", listen: "0.0.0.0:8017", publicURL: "https://hibp.lan", trustProxy: true, trustedCIDRs: "127.0.0.1/32", wantURL: "https://hibp.lan"},
		{name: "proxy public port differs", listen: "0.0.0.0:8017", publicURL: "https://hibp.lan:8443", trustProxy: true, trustedCIDRs: "10.0.0.0/8", wantURL: "https://hibp.lan:8443"},
		{name: "proxy with TLS", listen: "192.168.1.10:8443", cert: cert, key: key, publicURL: "https://hibp.lan", trustProxy: true, wantErr: true},
		{name: "proxy needs https public URL", listen: "127.0.0.1:8443", publicURL: "http://hibp.lan", trustProxy: true, wantErr: true},
		{name: "proxy invalid CIDR", listen: "0.0.0.0:8017", publicURL: "https://hibp.lan", trustProxy: true, trustedCIDRs: "not-a-cidr", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validateServerListen(test.listen, test.cert, test.key, test.publicURL, test.trustProxy, test.trustedCIDRs)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.TLS != test.wantTLS || got.PublicURL != test.wantURL || got.TrustProxy != test.trustProxy {
				t.Fatalf("got %+v, want TLS=%v proxy=%v URL=%q", got, test.wantTLS, test.trustProxy, test.wantURL)
			}
		})
	}
}

func testTLSKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "hibp.lan"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"hibp.lan", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.10")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		t.Fatal(err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
