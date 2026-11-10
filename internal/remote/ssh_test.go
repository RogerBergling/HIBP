package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func TestHostKeyCallbackUnknownAndChanged(t *testing.T) {
	key := testPublicKey(t)
	callback := hostKeyCallback(nil, nil)
	err := callback("host", &net.TCPAddr{}, key)
	var keyErr *KeyError
	if !errors.As(err, &keyErr) || keyErr.Kind != "unknown" {
		t.Fatalf("expected unknown key error, got %v", err)
	}
	if keyErr.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Fatal("fingerprint mismatch")
	}

	expected := &HostKey{KeyType: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
	if err := hostKeyCallback(expected, nil)("host", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("expected matching key to pass: %v", err)
	}

	other := testPublicKey(t)
	err = hostKeyCallback(expected, nil)("host", &net.TCPAddr{}, other)
	if !errors.As(err, &keyErr) || keyErr.Kind != "changed" {
		t.Fatalf("expected changed key error, got %v", err)
	}
}

func TestLoadSignerPermissions(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(path); err == nil {
		t.Fatal("expected world-readable key to fail")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(path); err != nil {
		t.Fatalf("expected 0600 key to parse: %v", err)
	}
}
