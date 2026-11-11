package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/buildinfo"
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
		Agent: buildinfo.Info{
			Version: "0.6.2", BuildNumber: "1234", BuildCommit: "abc123def456",
			BuildDate: "2026-11-11T12:00:00Z", BuildTarget: "linux/amd64", BuildType: "release",
		},
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
	if hosts[0].Facts.Agent.Version != "0.6.2" || hosts[0].Facts.Agent.BuildNumber != "1234" ||
		hosts[0].Facts.Agent.BuildCommit != "abc123def456" {
		t.Fatalf("unexpected agent build: %+v", hosts[0].Facts.Agent)
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

func TestBackupVerificationRejectsBrokenAuditChain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateHost(Host{Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519"}); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "backup.hibp")
	if err := s.Backup(backupPath); err != nil {
		t.Fatal(err)
	}
	db, err := openSQLCipher(backupPath, s.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE audit_log SET detail='tampered' WHERE id=(SELECT id FROM audit_log ORDER BY id LIMIT 1)"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = verifyBackup(backupPath, s.key)
	if err == nil || !strings.Contains(err.Error(), "audit chain") {
		t.Fatalf("expected audit-chain verification failure, got %v", err)
	}
}

func TestNewerSchemaVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(999,'future.sql','future','2026-11-11T00:00:00Z')"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dbPath, pass, Options{}); err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
		t.Fatalf("expected newer-schema refusal, got %v", err)
	}
}

func TestPendingMigrationCreatesAutomaticBackup(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DELETE FROM schema_migrations WHERE version=7"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopening tries to apply migration 007 again, which fails because the
	// column already exists. The automatic backup must exist regardless.
	if _, err := Open(dbPath, pass, Options{}); err == nil {
		t.Fatal("expected reapplying migration 007 to fail")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*-pre-migration-*.bac"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one automatic pre-migration backup, got %v", matches)
	}
	if _, err := os.Stat(matches[0] + ".meta"); err != nil {
		t.Fatalf("pre-migration backup sidecar missing: %v", err)
	}
}

func TestBackupConfigAndManagedRetention(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("fleet", "backup.directory", backupDir); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("fleet", "backup.retention_count", "3"); err != nil {
		t.Fatal(err)
	}
	gotDir, gotRetention := s.BackupConfig()
	if gotDir != backupDir || gotRetention != 3 {
		t.Fatalf("BackupConfig = %q, %d; want %q, 3", gotDir, gotRetention, backupDir)
	}

	base := time.Now().Add(-10 * time.Minute)
	for index := 0; index < 5; index++ {
		name := fmt.Sprintf("hibp-2026-01-%02d-030000.bac", index+1)
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("backup"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".meta", []byte("sidecar"), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp := base.Add(time.Duration(index) * time.Minute)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path+".meta", stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	unmanaged := filepath.Join(backupDir, "manual.bac")
	if err := os.WriteFile(unmanaged, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pruneManagedBackups(backupDir, 3); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	var managed int
	for _, entry := range entries {
		if managedBackupPattern.MatchString(entry.Name()) {
			managed++
		}
	}
	if managed != 3 {
		t.Fatalf("managed backups = %d, want 3", managed)
	}
	for _, name := range []string{"hibp-2026-01-01-030000.bac", "hibp-2026-01-02-030000.bac"} {
		if _, err := os.Stat(filepath.Join(backupDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be pruned, got %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(backupDir, name+".meta")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s.meta to be pruned, got %v", name, err)
		}
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Fatalf("unmanaged backup was removed: %v", err)
	}
}

func TestBackupRetentionAppliesToManagedFiles(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.hibp")
	pass := []byte("correct horse battery staple")
	s, err := Open(dbPath, pass, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("fleet", "backup.retention_count", "2"); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= 3; index++ {
		path := filepath.Join(backupDir, fmt.Sprintf("hibp-2026-01-%02d-030000.bac", index))
		if err := s.Backup(path); err != nil {
			t.Fatalf("backup %d: %v", index, err)
		}
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	var managed int
	for _, entry := range entries {
		if managedBackupPattern.MatchString(entry.Name()) {
			managed++
		}
	}
	if managed != 2 {
		t.Fatalf("managed backups = %d, want 2", managed)
	}
}
