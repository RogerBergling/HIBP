package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

func seedTestSession(t *testing.T, db *store.Store) {
	t.Helper()
	hash, err := auth.HashPassword("test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	user, err := db.CreateUser("test", hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSession(user.ID, auth.HashSessionToken("test-token"), true, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	return testServerWithUser(t, true)
}

func testServerNoUser(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	return testServerWithUser(t, false)
}

func testServerWithUser(t *testing.T, seedUser bool) (*httptest.Server, *store.Store) {
	t.Helper()
	ts, db, _ := testServerWithApp(t, seedUser)
	return ts, db
}

func testServerWithApp(t *testing.T, seedUser bool) (*httptest.Server, *store.Store, *Server) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sshDir := filepath.Join(dir, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sshConfigPath := filepath.Join(sshDir, "config")
	if err := os.WriteFile(sshConfigPath, []byte("Host testhost\n  HostName test.example\n  User ubuntu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if seedUser {
		seedTestSession(t, db)
	}
	app, err := New(Config{Store: db, Version: "test", SSHConfigPath: sshConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(app.Handler())
	t.Cleanup(ts.Close)
	return ts, db, app
}

func request(t *testing.T, method, url, token string, body string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func findSessionCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	t.Fatal("session cookie was not set")
	return nil
}

func TestAuthStatusSetupRequired(t *testing.T) {
	ts, _ := testServerNoUser(t)
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/auth/status", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var status struct {
		SetupRequired bool `json:"setup_required"`
		Authenticated bool `json:"authenticated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if !status.SetupRequired || status.Authenticated {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestSetupTOTPAndLoginFlow(t *testing.T) {
	ts, _ := testServerNoUser(t)
	base := ts.URL

	resp := request(t, http.MethodPost, base+"/api/v1/auth/setup", "", `{"username":"admin","password":"correct horse battery staple"}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("setup failed: %d %s", resp.StatusCode, data)
	}
	cookie := findSessionCookie(t, resp)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure {
		resp.Body.Close()
		t.Fatalf("unexpected session cookie flags: %+v", cookie)
	}
	pending := cookie.Value
	resp.Body.Close()

	resp = request(t, http.MethodGet, base+"/api/v1/auth/status", pending, "")
	var status struct {
		SetupRequired         bool `json:"setup_required"`
		Authenticated         bool `json:"authenticated"`
		MFARequired           bool `json:"mfa_required"`
		MFAEnrollmentRequired bool `json:"mfa_enrollment_required"`
		WebAuthnAvailable     bool `json:"webauthn_available"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if status.SetupRequired || status.Authenticated || !status.MFARequired || !status.MFAEnrollmentRequired {
		t.Fatalf("unexpected pending status: %+v", status)
	}
	if status.WebAuthnAvailable {
		t.Fatal("passkeys must not be advertised for 127.0.0.1")
	}

	resp = request(t, http.MethodPost, base+"/api/v1/auth/totp/begin", pending, `{}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("totp begin failed: %d %s", resp.StatusCode, data)
	}
	var totp struct {
		Secret string `json:"secret"`
		QR     string `json:"qr_png"`
		URI    string `json:"uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&totp); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if totp.Secret == "" || !strings.HasPrefix(totp.QR, "data:image/png;base64,") || !strings.HasPrefix(totp.URI, "otpauth://totp/") {
		t.Fatalf("unexpected TOTP setup: %+v", totp)
	}
	enrollCode, _, err := auth.TOTPCode(totp.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, base+"/api/v1/auth/totp/verify", pending, fmt.Sprintf(`{"code":%q}`, enrollCode))
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("totp verify failed: %d %s", resp.StatusCode, data)
	}
	fullCookie := findSessionCookie(t, resp)
	full := fullCookie.Value
	resp.Body.Close()
	if full == pending {
		t.Fatal("session token was not rotated after MFA")
	}

	resp = request(t, http.MethodGet, base+"/api/v1/auth/status", full, "")
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if !status.Authenticated || status.MFARequired || status.MFAEnrollmentRequired {
		t.Fatalf("unexpected authenticated status: %+v", status)
	}
	resp = request(t, http.MethodGet, base+"/api/v1/hosts", full, "")
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("authenticated hosts request failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	// Log out, log in again, and prove that a pending session cannot reach
	// application data or rotate TOTP with only the password.
	// the password.
	resp = request(t, http.MethodPost, base+"/api/v1/auth/logout", full, `{}`)
	resp.Body.Close()
	resp = request(t, http.MethodPost, base+"/api/v1/auth/login", "", `{"username":"admin","password":"correct horse battery staple"}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login failed: %d %s", resp.StatusCode, data)
	}
	pending2 := findSessionCookie(t, resp).Value
	resp.Body.Close()
	resp = request(t, http.MethodGet, base+"/api/v1/hosts", pending2, "")
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("expected 403 for pending session, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(t, http.MethodPost, base+"/api/v1/auth/totp/begin", pending2, `{}`)
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatalf("pending session could rotate TOTP: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Use the next time step so the code is definitely newer than enrollment.
	loginCode, _, err := auth.TOTPCode(totp.Secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, base+"/api/v1/auth/totp/verify", pending2, fmt.Sprintf(`{"code":%q}`, loginCode))
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login TOTP failed: %d %s", resp.StatusCode, data)
	}
	full2 := findSessionCookie(t, resp).Value
	resp.Body.Close()

	// Replay the same TOTP from a fresh pending session.
	resp = request(t, http.MethodPost, base+"/api/v1/auth/logout", full2, `{}`)
	resp.Body.Close()
	resp = request(t, http.MethodPost, base+"/api/v1/auth/login", "", `{"username":"admin","password":"correct horse battery staple"}`)
	pending3 := findSessionCookie(t, resp).Value
	resp.Body.Close()
	resp = request(t, http.MethodPost, base+"/api/v1/auth/totp/verify", pending3, fmt.Sprintf(`{"code":%q}`, loginCode))
	var replay struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&replay); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || replay.Code != "replayed_code" {
		t.Fatalf("expected replayed_code rejection, got %d %+v", resp.StatusCode, replay)
	}
}

func TestSetupRejectedWhenUserExists(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/setup", "", `{"username":"other","password":"correct horse battery staple"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, _ := testServer(t)
	for attempt := 0; attempt < 5; attempt++ {
		resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/login", "", `{"username":"test","password":"wrong password"}`)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", attempt+1, resp.StatusCode)
		}
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/login", "", `{"username":"test","password":"wrong password"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

func TestWebAuthnConfigRequiresLocalhost(t *testing.T) {
	s := &Server{}
	request := httptest.NewRequest(http.MethodPost, "http://localhost:8443/api/v1/auth/passkey/register/begin", nil)
	request.Host = "localhost:8443"
	rpID, origin, err := s.webAuthnConfig(request)
	if err != nil || rpID != "localhost" || origin != "http://localhost:8443" {
		t.Fatalf("unexpected localhost config: rpID=%q origin=%q err=%v", rpID, origin, err)
	}
	request.Host = "127.0.0.1:8443"
	if _, _, err := s.webAuthnConfig(request); err == nil {
		t.Fatal("expected IP-address RP ID to be rejected")
	}
	request.Host = "evil.example:8443"
	if _, _, err := s.webAuthnConfig(request); err == nil {
		t.Fatal("expected non-localhost RP ID to be rejected")
	}
}

func TestWebAuthnUserAdaptsStoredPasskey(t *testing.T) {
	_, db := testServer(t)
	s := &Server{store: db}
	user, err := db.GetUserByUsername("test")
	if err != nil {
		t.Fatal(err)
	}
	credentialJSON, err := json.Marshal(webauthn.Credential{ID: []byte("credential-1"), PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddPasskey(user.ID, []byte("credential-1"), string(credentialJSON), 0, "Test"); err != nil {
		t.Fatal(err)
	}
	waUser, err := s.webAuthnUser(user)
	if err != nil {
		t.Fatal(err)
	}
	if string(waUser.WebAuthnID()) != user.ID || waUser.WebAuthnName() != "test" {
		t.Fatalf("unexpected WebAuthn user: %+v", waUser)
	}
	credentials := waUser.WebAuthnCredentials()
	if len(credentials) != 1 || string(credentials[0].ID) != "credential-1" {
		t.Fatalf("unexpected credentials: %+v", credentials)
	}
}

func TestCeremonyStoreIsBoundAndSingleUse(t *testing.T) {
	store := newCeremonyStore()
	data := webauthn.SessionData{Challenge: "challenge", UserID: []byte("user-1")}
	id, err := store.put("session-1", "user-1", "login", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.take(id, "session-2", "user-1", "login"); err == nil {
		t.Fatal("ceremony accepted from the wrong session")
	}
	if _, err := store.take(id, "session-1", "user-1", "login"); err == nil {
		t.Fatal("ceremony was not consumed on the first take")
	}
	id, err = store.put("session-1", "user-1", "login", data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.take(id, "session-1", "user-1", "login")
	if err != nil {
		t.Fatal(err)
	}
	if got.Challenge != "challenge" {
		t.Fatalf("unexpected ceremony data: %+v", got)
	}
}

func TestPasskeysUnavailableOnIPOrigin(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/passkey/register/begin", "test-token", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "passkey_unavailable" {
		t.Fatalf("expected passkey_unavailable, got %q", payload.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/hosts", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts", "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestStatusIncludesBuildInformation(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := buildinfo.Info{
		Version: "0.6.2", BuildNumber: "1234", BuildCommit: "abc123def456",
		BuildDate: "2026-11-11T12:00:00Z", BuildTarget: "linux/amd64", BuildType: "release",
	}
	app, err := New(Config{Store: db, Build: want, SSHConfigPath: filepath.Join(dir, "missing-config")})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	app.handleStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	var response struct {
		Version string         `json:"version"`
		Build   buildinfo.Info `json:"build"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Version != want.Version || response.Build != want {
		t.Fatalf("unexpected build response: %+v", response)
	}
}

func TestCreateAndListHost(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","tags":"web,prod"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	if host.ID == "" {
		t.Fatal("expected id")
	}

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts", "test-token", "")
	defer resp.Body.Close()
	var list struct {
		Hosts []store.Host `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Hosts) != 1 || list.Hosts[0].Name != "web01" {
		t.Fatalf("unexpected hosts: %+v", list.Hosts)
	}
}

func TestUpdateHost(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","tags":"web,prod"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	update := `{"name":"web01-updated","address":"10.0.0.11","port":2222,"username":"admin","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","tags":"web,prod,updated","group_name":"web-prod","cmdb_ci_id":"CI-999"}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, strings.NewReader(update))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-token"})
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("update failed: %d %s", resp.StatusCode, data)
	}
	var updated store.Host
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "web01-updated" || updated.Address != "10.0.0.11" || updated.Port != 2222 {
		t.Fatalf("unexpected updated host: %+v", updated)
	}
}

func TestListSSHKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedTestSession(t, db)
	app, err := New(Config{Store: db, Version: "test", KeyDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(app.Handler())
	t.Cleanup(ts.Close)

	resp := request(t, http.MethodGet, ts.URL+"/api/v1/keys?path="+url.QueryEscape(dir), "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("list keys failed: %d %s", resp.StatusCode, data)
	}
	var result struct {
		Entries []keyEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %+v", result.Entries)
	}
	if !result.Entries[0].IsDir {
		t.Fatalf("expected directory first, got %+v", result.Entries)
	}

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/keys?path="+url.QueryEscape(filepath.Dir(dir)), "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected traversal to be forbidden, got %d", resp.StatusCode)
	}
}

func TestSecurityHeadersAndOrigin(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodGet, ts.URL+"/", "", "")
	defer resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options")
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("missing CSP")
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/hosts", bytes.NewBufferString(`{}`))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-token"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for bad origin, got %d", resp.StatusCode)
	}
}

func TestImportPreviewAndCommit(t *testing.T) {
	ts, _ := testServer(t)
	payload := map[string]any{
		"csv":              "name,address,port,username,auth_type,key_path\nweb01,10.0.0.10,22,ubuntu,key,/home/ops/.ssh/id_ed25519\ndb01,10.0.0.20,22,root,key,/home/ops/.ssh/id_ed25519\n",
		"commit":           false,
		"duplicate_policy": "error",
	}
	body, _ := json.Marshal(payload)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("preview failed: %d %s", resp.StatusCode, data)
	}
	var result importResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Imported != 0 || len(result.Rows) != 2 {
		t.Fatalf("unexpected preview: %+v", result)
	}

	payload["commit"] = true
	body, _ = json.Marshal(payload)
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("commit failed: %d %s", resp.StatusCode, data)
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %+v", result)
	}
}

func TestTXTImport(t *testing.T) {
	ts, _ := testServer(t)
	payload := map[string]any{
		"csv":              "# one host per line\nweb01\nubuntu@10.0.0.11:2222\n",
		"commit":           true,
		"duplicate_policy": "error",
		"default_key_path": "/home/ops/.ssh/id_ed25519",
	}
	body, _ := json.Marshal(payload)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("TXT import failed: %d %s", resp.StatusCode, data)
	}
	var result importResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 {
		t.Fatalf("expected 2 imported, got %+v", result)
	}
}

func TestPasswordAuthRequiresManualPassword(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"legacy01","address":"10.0.0.30","port":22,"username":"root","auth_type":"password"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("create failed: %d %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/test", "test-token", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 without password, got %d", resp.StatusCode)
	}
}

func TestSSHConfigEndpoint(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/ssh/config", "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, data)
	}
	var payload struct {
		Exists bool `json:"exists"`
		Hosts  []struct {
			Alias    string `json:"alias"`
			HostName string `json:"hostname"`
			Port     int    `json:"port"`
			User     string `json:"user"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Exists || len(payload.Hosts) != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	host := payload.Hosts[0]
	if host.Alias != "testhost" || host.HostName != "test.example" || host.Port != 22 || host.User != "ubuntu" {
		t.Fatalf("unexpected host: %+v", host)
	}
}

func TestRebootRequiresConfirmation(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/reboot", "test-token", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, data)
	}
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "confirm") {
		t.Fatalf("expected confirmation error, got %s", data)
	}
}

func TestSettingsEndpoints(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/settings", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get settings failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", `{"scope":"fleet","settings":{"collector.metrics_interval":"1m","metrics.retention_days":"14"}}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("put settings failed: %d %s", resp.StatusCode, data)
	}
	var payload struct {
		Resolved map[string]string `json:"resolved"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if payload.Resolved["collector.metrics_interval"] != "1m" || payload.Resolved["metrics.retention_days"] != "14" {
		t.Fatalf("unexpected settings: %#v", payload.Resolved)
	}
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", `{"scope":"fleet","settings":{"collector.metrics_interval":"2s"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("expected invalid interval rejection, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestHostDetailsEndpoint(t *testing.T) {
	ts, db := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create host failed: %d %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := db.SaveSystemInfo(host.ID, "2026-11-11T07:00:00Z", `{"hostname":"web01","cpu":{"usage_percent":12.5}}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveMetrics(host.ID, store.MetricSample{CollectedAt: "2026-11-11T07:00:00Z", CPUPercent: 12.5, MemoryPercent: 30}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDockerInventory(host.ID,
		[]store.DockerProject{{Name: "web", Status: "running(1)", ConfigFiles: "/opt/web/compose.yaml"}},
		[]store.DockerContainer{{ContainerID: "abc", Name: "web-1", Project: "web", Service: "frontend", Image: "nginx", State: "running", Health: "healthy"}}); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details", "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("details failed: %d %s", resp.StatusCode, data)
	}
	var details struct {
		SystemInfo map[string]any          `json:"system_info"`
		Metrics    []store.MetricSample    `json:"metrics"`
		Projects   []store.DockerProject   `json:"docker_projects"`
		Containers []store.DockerContainer `json:"docker_containers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		t.Fatal(err)
	}
	if details.SystemInfo["hostname"] != "web01" || len(details.Metrics) != 1 || len(details.Projects) != 1 || len(details.Containers) != 1 {
		t.Fatalf("unexpected details: %+v", details)
	}
}

func TestDockerActionValidation(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/check", "test-token", `{"project":"bad project"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid project rejection, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/apply", "test-token", `{"project":"web"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected missing apply confirmation rejection, got %d", resp.StatusCode)
	}
}

func TestBootstrapRequiresTrustedHostKey(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201, got %d: %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/bootstrap", "test-token", `{}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 409, got %d: %s", resp.StatusCode, data)
	}
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "host_key_untrusted" {
		t.Fatalf("expected host_key_untrusted, got %q", payload.Code)
	}
}

func TestSudoPasswordInvalidDetection(t *testing.T) {
	for _, output := range []string{
		"Sorry, try again.",
		"sudo: incorrect password",
		"Authentication failure",
		"sudo: Authentication failed, try again. sudo: Authentication required but not attempted",
	} {
		if !looksLikeSudoPasswordInvalid(output) {
			t.Fatalf("expected invalid sudo password for %q", output)
		}
	}
	if looksLikeSudoPasswordInvalid("Reading package lists...") {
		t.Fatal("normal package output must not be classified as invalid sudo password")
	}
}

func TestSudoAuthFailureDetection(t *testing.T) {
	for _, output := range []string{
		"sudo: interactive authentication is required",
		"sudo: a password is required",
		"sudo: Authentication failed, try again. sudo: Authentication required but not attempted",
		"sudo: no tty present and no askpass program specified",
		"sudo: a terminal is required to read the password",
	} {
		if !looksLikeSudoAuthFailure(output) {
			t.Fatalf("expected sudo auth failure for %q", output)
		}
	}
	if looksLikeSudoAuthFailure("Reading package lists...") {
		t.Fatal("normal package output must not be classified as sudo failure")
	}
}

func TestExportNeutralizesCSVInjection(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"=cmd","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("create failed: %d %s", resp.StatusCode, data)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/export/hosts.csv", "test-token", "")
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(data), "'=cmd") {
		t.Fatalf("expected neutralized CSV, got %q", data)
	}
}
