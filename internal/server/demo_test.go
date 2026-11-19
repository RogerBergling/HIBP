//go:build demo

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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

func TestDemoGuestCanLogInWithDisplayedTOTP(t *testing.T) {
	db := openDemoTestStore(t)
	app, err := New(Config{
		Store:         db,
		Version:       "test",
		SSHConfigPath: filepath.Join(t.TempDir(), "missing-config"),
		// The test client reaches the server over HTTP. A configured HTTPS
		// public URL must not force a Secure cookie over that HTTP transport,
		// or the cookie jar drops it and the demo loops back to the login form.
		PublicURL: "https://demo.example:8443",
		Demo:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(app.Handler())
	defer ts.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	post := func(path, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp, err := client.Get(ts.URL + "/api/v1/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Demo struct {
			TOTPCode string `json:"totp_code"`
		} `json:"demo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if status.Demo.TOTPCode == "" {
		t.Fatal("demo status did not include a TOTP code")
	}

	resp = post("/api/v1/auth/login", `{"username":"guest","password":"guest"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}
	resp = post("/api/v1/auth/totp/verify", `{"code":"`+status.Demo.TOTPCode+`"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("TOTP verify: expected 200, got %d", resp.StatusCode)
	}
	resp, err = client.Get(ts.URL + "/api/v1/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request: expected 200, got %d", resp.StatusCode)
	}
}

func TestDemoGuestCanLogInWithoutCookies(t *testing.T) {
	db := openDemoTestStore(t)
	app, err := New(Config{
		Store:         db,
		Version:       "test",
		SSHConfigPath: filepath.Join(t.TempDir(), "missing-config"),
		PublicURL:     "https://demo.example:8443",
		Demo:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(app.Handler())
	defer ts.Close()
	client := &http.Client{} // deliberately no cookie jar

	do := func(method, path, body, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set(demoSessionHeader, token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	type authStatus struct {
		Authenticated bool `json:"authenticated"`
		MFARequired   bool `json:"mfa_required"`
		Demo          struct {
			TOTPCode string `json:"totp_code"`
		} `json:"demo"`
	}

	resp := do(http.MethodGet, "/api/v1/auth/status", "", "")
	var initial authStatus
	if err := json.NewDecoder(resp.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if initial.Demo.TOTPCode == "" {
		t.Fatal("demo status did not include a TOTP code")
	}

	resp = do(http.MethodPost, "/api/v1/auth/login", `{"username":"guest","password":"guest"}`, "")
	pendingToken := resp.Header.Get(demoSessionHeader)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || pendingToken == "" {
		t.Fatalf("login: status=%d demo token=%q", resp.StatusCode, pendingToken)
	}

	resp = do(http.MethodGet, "/api/v1/auth/status", "", pendingToken)
	var pending authStatus
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !pending.MFARequired || pending.Authenticated {
		t.Fatalf("pending status: authenticated=%v mfa_required=%v", pending.Authenticated, pending.MFARequired)
	}

	resp = do(http.MethodPost, "/api/v1/auth/totp/verify", `{"code":"`+initial.Demo.TOTPCode+`"}`, pendingToken)
	completedToken := resp.Header.Get(demoSessionHeader)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || completedToken == "" {
		t.Fatalf("TOTP verify: status=%d demo token=%q", resp.StatusCode, completedToken)
	}

	resp = do(http.MethodGet, "/api/v1/auth/status", "", completedToken)
	var completed authStatus
	if err := json.NewDecoder(resp.Body).Decode(&completed); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !completed.Authenticated {
		t.Fatal("expected the demo token to authenticate without cookies")
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
