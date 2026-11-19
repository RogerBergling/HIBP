//go:build demo

package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

func openDemoTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "demo.db"), []byte("demo-test-passphrase"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := SeedDemo(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSeedDemoGuestAndData(t *testing.T) {
	db := openDemoTestStore(t)
	users, err := db.CountUsers()
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := db.CountHosts()
	if err != nil {
		t.Fatal(err)
	}
	if users != 1 || hosts != 8 {
		t.Fatalf("unexpected seed counts: users=%d hosts=%d", users, hosts)
	}
	user, err := db.GetUserByUsername(demoUsername)
	if err != nil {
		t.Fatal(err)
	}
	if !user.TOTPEnabled {
		t.Fatal("expected demo TOTP to be enabled")
	}
	hooks := newDemoHooks(db)
	info := hooks.AuthInfo()
	secret, _ := info["totp_secret"].(string)
	code, _ := info["totp_code"].(string)
	if secret == "" || code == "" {
		t.Fatalf("missing demo TOTP info: %+v", info)
	}
	if _, ok := auth.ValidateTOTP(secret, code, time.Now()); !ok {
		t.Fatal("demo TOTP code did not validate")
	}
}

func TestDemoHelperContracts(t *testing.T) {
	db := openDemoTestStore(t)
	hooks := newDemoHooks(db)
	hosts, err := db.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	var host store.Host
	for _, candidate := range hosts {
		if candidate.Name == "web01" {
			host = candidate
			break
		}
	}
	if host.ID == "" {
		t.Fatal("web01 not seeded")
	}
	ctx := context.Background()

	out, code, err := hooks.RunHelper(ctx, host, "facts", "", time.Minute)
	if err != nil || code != 0 {
		t.Fatalf("facts failed: %v code=%d", err, code)
	}
	var facts helper.Facts
	if err := json.Unmarshal([]byte(out), &facts); err != nil {
		t.Fatal(err)
	}
	if facts.PackageManager != "apt" || facts.Agent.Version == "" {
		t.Fatalf("unexpected facts: %+v", facts)
	}

	out, _, err = hooks.RunHelper(ctx, host, "preview", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var preview helper.PreviewResult
	if err := json.Unmarshal([]byte(out), &preview); err != nil {
		t.Fatal(err)
	}
	if !preview.OK || len(preview.Packages) == 0 {
		t.Fatalf("unexpected preview: %+v", preview)
	}

	out, _, err = hooks.RunHelper(ctx, host, "system-info", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var info helper.SystemInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatal(err)
	}
	if info.Hostname != "web01" || !info.Systemd.Available {
		t.Fatalf("unexpected system info: %+v", info)
	}

	out, _, err = hooks.RunHelper(ctx, host, "docker-list", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var inventory helper.DockerInventory
	if err := json.Unmarshal([]byte(out), &inventory); err != nil {
		t.Fatal(err)
	}
	if !inventory.Available || len(inventory.Projects) == 0 {
		t.Fatalf("unexpected docker inventory: %+v", inventory)
	}

	out, _, err = hooks.RunHelper(ctx, host, "cleanup-check", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var cleanup helper.CleanupResult
	if err := json.Unmarshal([]byte(out), &cleanup); err != nil {
		t.Fatal(err)
	}
	if !cleanup.OK || cleanup.Count == 0 {
		t.Fatalf("unexpected cleanup: %+v", cleanup)
	}

	request, _ := json.Marshal(helper.InstallPackageRequest{
		Filename: "wazuh-agent_demo_amd64.deb", SHA256: strings.Repeat("0", 64),
		Env: map[string]string{"WAZUH_MANAGER": "10.20.0.5"},
	})
	out, _, err = hooks.RunHelper(ctx, host, "install-package", string(request), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var install helper.PackageInstallResult
	if err := json.Unmarshal([]byte(out), &install); err != nil {
		t.Fatal(err)
	}
	if !install.OK || install.Package != "wazuh-agent_demo_amd64.deb" {
		t.Fatalf("unexpected install result: %+v", install)
	}
}

func TestDemoHostTrustAndMonitor(t *testing.T) {
	db := openDemoTestStore(t)
	hooks := newDemoHooks(db)
	hosts, err := db.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	var untrusted store.Host
	for _, candidate := range hosts {
		if candidate.Name == "web02" {
			untrusted = candidate
			break
		}
	}
	if untrusted.ID == "" {
		t.Fatal("web02 not seeded")
	}
	err = hooks.TestHost(context.Background(), untrusted, "")
	var keyErr *remote.KeyError
	if !errors.As(err, &keyErr) || keyErr.Kind != "unknown" {
		t.Fatalf("expected unknown key error, got %v", err)
	}
	key, err := hooks.ProbeHost(context.Background(), untrusted, "")
	if err != nil || key.Fingerprint == "" {
		t.Fatalf("probe failed: %v %+v", err, key)
	}
	if err := db.SaveHostKey(store.HostKey{HostID: untrusted.ID, KeyType: key.KeyType, Fingerprint: key.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	if err := hooks.TestHost(context.Background(), untrusted, ""); err != nil {
		t.Fatalf("trusted host test failed: %v", err)
	}

	status, message := hooks.EvaluateNetworkMonitor(context.Background(), store.Monitor{Type: "http", Target: "https://fail.example.invalid"})
	if status != "critical" || message == "" {
		t.Fatalf("unexpected failure monitor: %s %s", status, message)
	}
	status, _ = hooks.EvaluateNetworkMonitor(context.Background(), store.Monitor{Type: "http", Target: "https://ok.example.invalid"})
	if status != "ok" {
		t.Fatalf("unexpected healthy monitor: %s", status)
	}
	if err := hooks.SendEmail(mailer.Config{}, nil, "demo", "demo"); err != nil {
		t.Fatalf("demo email should be simulated: %v", err)
	}
}
