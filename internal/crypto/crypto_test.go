package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSidecarRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	sidecar, key, err := CreateSidecarWithParams(dbPath, pass, 1, 64*1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeyLen {
		t.Fatalf("expected %d-byte key, got %d", KeyLen, len(key))
	}
	if _, err := os.Stat(SidecarPath(dbPath)); err != nil {
		t.Fatal(err)
	}
	read, err := ReadSidecar(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if read.Checksum != sidecar.Checksum {
		t.Fatal("checksum mismatch")
	}
	key2, err := DeriveKey(pass, read)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != string(key2) {
		t.Fatal("derived keys differ")
	}
}

func TestSidecarTamper(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	if _, _, err := CreateSidecarWithParams(dbPath, []byte("correct horse battery staple"), 1, 64*1024, 1); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(SidecarPath(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"time": 1`, `"time": 2`, 1))
	if err := os.WriteFile(SidecarPath(dbPath), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSidecar(dbPath); err == nil {
		t.Fatal("expected tampered sidecar to fail")
	}
}

func TestShortPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := CreateSidecarWithParams(filepath.Join(dir, "x.hibp"), []byte("short"), 1, 64*1024, 1); err == nil {
		t.Fatal("expected short passphrase to fail")
	}
}

func TestToken(t *testing.T) {
	token, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(token))
	}
	if !EqualToken(token, token) {
		t.Fatal("token should equal itself")
	}
	if EqualToken(token, token+"x") {
		t.Fatal("different tokens should not match")
	}
}
