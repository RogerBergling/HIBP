package sshconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findHost(t *testing.T, hosts []Host, alias string) Host {
	t.Helper()
	for _, host := range hosts {
		if host.Alias == alias {
			return host
		}
	}
	t.Fatalf("host %q not found in %#v", alias, hosts)
	return Host{}
}

func TestLoadParsesConcreteHosts(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	writeConfig(t, filepath.Join(sshDir, "id_ed25519"), "key")
	config := `# sample config
Host web1
  HostName 10.0.0.10
  User ubuntu
  Port 2222
  IdentityFile ~/.ssh/id_ed25519

Host db1 db2
  HostName db.example.com
  IdentityFile id_rsa

Host *.internal
  User ignored

Match host foo
  User ignored

Host *
  User ignored
`
	path := filepath.Join(sshDir, "config")
	writeConfig(t, path, config)

	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d: %#v", len(hosts), hosts)
	}
	if hosts[0].Alias != "db1" || hosts[1].Alias != "db2" || hosts[2].Alias != "web1" {
		t.Fatalf("unexpected host order: %#v", hosts)
	}

	web := findHost(t, hosts, "web1")
	if web.HostName != "10.0.0.10" || web.Port != 2222 || web.User != "ubuntu" {
		t.Fatalf("unexpected web host: %#v", web)
	}
	if web.KeyPath != filepath.Join(sshDir, "id_ed25519") {
		t.Fatalf("unexpected web key path: %q", web.KeyPath)
	}

	db := findHost(t, hosts, "db1")
	if db.HostName != "db.example.com" || db.Port != 22 || db.User == "" {
		t.Fatalf("unexpected db host: %#v", db)
	}
	if db.KeyPath != filepath.Join(sshDir, "id_rsa") {
		t.Fatalf("unexpected db key path: %q", db.KeyPath)
	}
}

func TestLoadFirstValueWinsAndLaterFieldsFill(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "config")
	writeConfig(t, path, `Host web
  User first
  HostName host1

Host web
  User second
  HostName host2
  Port 2200
`)
	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	web := findHost(t, hosts, "web")
	if web.User != "first" {
		t.Fatalf("expected first user to win, got %q", web.User)
	}
	if web.HostName != "host1" {
		t.Fatalf("expected first hostname to win, got %q", web.HostName)
	}
	if web.Port != 2200 {
		t.Fatalf("expected later port to fill the unset field, got %d", web.Port)
	}
}

func TestLoadIncludes(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	path := filepath.Join(sshDir, "config")
	writeConfig(t, path, "Include conf.d/*.conf\n")
	writeConfig(t, filepath.Join(sshDir, "conf.d", "a.conf"), "Host included\n  HostName inc.example\n  User ops\n")
	writeConfig(t, filepath.Join(sshDir, "conf.d", "b.conf"), "Host included2\n  HostName inc2.example\n")

	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 included hosts, got %d: %#v", len(hosts), hosts)
	}
	if findHost(t, hosts, "included").HostName != "inc.example" {
		t.Fatalf("unexpected included host: %#v", hosts)
	}
	if findHost(t, hosts, "included2").HostName != "inc2.example" {
		t.Fatalf("unexpected included host: %#v", hosts)
	}
}

func TestLoadIncludeAfterHostBlock(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	path := filepath.Join(sshDir, "config")
	writeConfig(t, path, "Host first\n  HostName first.example\nInclude conf.d/*.conf\n")
	writeConfig(t, filepath.Join(sshDir, "conf.d", "extra.conf"), "Host second\n  HostName second.example\n")

	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %#v", len(hosts), hosts)
	}
	if findHost(t, hosts, "first").HostName != "first.example" {
		t.Fatalf("unexpected first host: %#v", hosts)
	}
	if findHost(t, hosts, "second").HostName != "second.example" {
		t.Fatalf("unexpected second host: %#v", hosts)
	}
}

func TestLoadMissingFile(t *testing.T) {
	home := t.TempDir()
	_, err := loadWithHome(filepath.Join(home, ".ssh", "missing"), home)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestLoadDefaultKeyAndInvalidPort(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	writeConfig(t, filepath.Join(sshDir, "id_ed25519"), "key")
	path := filepath.Join(sshDir, "config")
	writeConfig(t, path, "Host defaultkey\n  HostName example.com\n  Port not-a-port\n")
	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	host := findHost(t, hosts, "defaultkey")
	if host.Port != 22 {
		t.Fatalf("expected default port 22, got %d", host.Port)
	}
	if host.KeyPath != filepath.Join(sshDir, "id_ed25519") {
		t.Fatalf("expected default key path, got %q", host.KeyPath)
	}
}

func TestLoadExpandsIdentityTokens(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "config")
	writeConfig(t, path, `Host tokens
  HostName example.com
  User deploy
  IdentityFile %d/.ssh/custom-%u-%h
`)
	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	host := findHost(t, hosts, "tokens")
	want := filepath.Join(home, ".ssh", "custom-deploy-example.com")
	if host.KeyPath != want {
		t.Fatalf("expected %q, got %q", want, host.KeyPath)
	}
}

func TestLoadMultipleIdentityFilesAndGlobalDefaults(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	path := filepath.Join(sshDir, "config")
	writeConfig(t, path, `Host web
  HostName web.example
  IdentityFile ~/.ssh/id_ed25519
  IdentityFile ~/.ssh/id_rsa
  IdentityFile ~/.ssh/id_ed25519.pub

Host web
  IdentityFile ~/.ssh/work_key

Host db
  HostName db.example

Host *
  IdentityFile ~/.ssh/global_key
  IdentityFile ~/.ssh/global_key.pub
`)
	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %#v", len(hosts), hosts)
	}
	web := findHost(t, hosts, "web")
	wantWeb := []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "work_key"),
		filepath.Join(sshDir, "global_key"),
	}
	if len(web.IdentityFiles) != len(wantWeb) {
		t.Fatalf("expected %d identity files, got %#v", len(wantWeb), web.IdentityFiles)
	}
	for index, want := range wantWeb {
		if web.IdentityFiles[index] != want {
			t.Fatalf("identity file %d: expected %q, got %q", index, want, web.IdentityFiles[index])
		}
	}
	if web.KeyPath != wantWeb[0] {
		t.Fatalf("expected primary key %q, got %q", wantWeb[0], web.KeyPath)
	}
	db := findHost(t, hosts, "db")
	if len(db.IdentityFiles) != 1 || db.IdentityFiles[0] != filepath.Join(sshDir, "global_key") {
		t.Fatalf("expected global identity file on db, got %#v", db.IdentityFiles)
	}
	for _, host := range hosts {
		for _, key := range host.IdentityFiles {
			if strings.HasSuffix(strings.ToLower(key), ".pub") {
				t.Fatalf("public key leaked into identity files: %q", key)
			}
		}
	}
}

func TestLoadWildcardOnlyReturnsEmpty(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "config")
	writeConfig(t, path, "Host *\n  User ignored\n")
	hosts, err := loadWithHome(path, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Fatalf("expected no concrete hosts, got %#v", hosts)
	}
}
