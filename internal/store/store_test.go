package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testOptions() Options {
	return Options{Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1}
}

func TestCreateHostAuditBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")

	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "web,prod",
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	if host.ID == "" {
		t.Fatal("expected host id")
	}
	if err := s.SaveFacts(host.ID, Facts{
		CollectedAt: "2026-11-10T12:00:00Z", UptimeSeconds: 3600,
		Kernel: "6.8.0-51", OSPrettyName: "Ubuntu 24.04 LTS",
		PackageManager: "apt", PendingUpdates: 4, RebootRequired: true, TimeSyncOK: true,
	}); err != nil {
		t.Fatalf("save facts: %v", err)
	}
	hosts, err := s.ListHosts()
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Facts == nil || hosts[0].Facts.PendingUpdates != 4 {
		t.Fatalf("unexpected facts: %+v", hosts[0].Facts)
	}
	if err := s.VerifyAudit(); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	entries, err := s.ListAudit(10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected audit entries, got %d", len(entries))
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("web01")) {
		t.Fatal("plaintext host name found in encrypted database")
	}
	for _, path := range []string{dbPath, dbPath + ".meta"} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %o, want 600", path, info.Mode().Perm())
		}
	}

	backupPath := filepath.Join(dir, "backup.hibp")
	if err := s.Backup(backupPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := os.Stat(backupPath + ".meta"); err != nil {
		t.Fatalf("backup sidecar missing: %v", err)
	}
	restorePath := filepath.Join(dir, "restored.hibp")
	if err := s.Restore(backupPath, restorePath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, path := range []string{backupPath, restorePath} {
		restored, err := Open(path, pass, Options{})
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		hosts, err = restored.ListHosts()
		if err != nil {
			t.Fatalf("list %s: %v", path, err)
		}
		if len(hosts) != 1 || hosts[0].Name != "web01" {
			t.Fatalf("unexpected hosts in %s: %+v", path, hosts)
		}
		_ = restored.Close()
	}
}

func TestWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	s, err := Open(dbPath, []byte("correct horse battery staple"), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dbPath, []byte("wrong horse battery staple"), Options{}); err == nil {
		t.Fatal("expected wrong passphrase to fail")
	}
}

func TestUpdateAndDeleteHost(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	s, err := Open(dbPath, []byte("correct horse battery staple"), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	host, err := s.CreateHost(Host{Name: "db01", Address: "10.0.0.20", Port: 22, Username: "root", AuthType: "key", KeyPath: "/root/.ssh/id_ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	host.Name = "db01-renamed"
	if _, err := s.UpdateHost(host); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHost(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "db01-renamed" {
		t.Fatalf("expected rename, got %q", got.Name)
	}
	if err := s.DeleteHost(host.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHost(host.ID); err == nil {
		t.Fatal("expected deleted host to be gone")
	}
}
