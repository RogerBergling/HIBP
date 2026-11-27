package server

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/RogerBergling/hibp/internal/helper"
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
	return testServerWithConfig(t, seedUser, nil)
}

func testServerWithConfig(t *testing.T, seedUser bool, mutate func(*Config)) (*httptest.Server, *store.Store, *Server) {
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
	cfg := Config{Store: db, Version: "test", SSHConfigPath: sshConfigPath}
	if mutate != nil {
		mutate(&cfg)
	}
	app, err := New(cfg)
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

func TestThemeEndpointUsesConfiguredDefault(t *testing.T) {
	t.Setenv("APP_THEME", "light")
	ts, _ := testServer(t)
	resp := request(t, http.MethodGet, ts.URL+"/theme.js", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "javascript") {
		t.Fatalf("unexpected Content-Type: %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `var configured = "light"`) {
		t.Fatalf("theme.js did not carry the configured default: %s", text)
	}
	if !strings.Contains(text, "hibp-theme") {
		t.Fatal("theme.js does not read the saved theme")
	}
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

func TestConfiguredPublicURLAllowsLANHost(t *testing.T) {
	ts, _, app := testServerWithConfig(t, true, func(cfg *Config) {
		cfg.PublicURL = "https://hibp.lan:8443"
	})
	if !app.hostAllowed("hibp.lan") || !app.hostAllowed("localhost") || !app.hostAllowed("127.0.0.1") {
		t.Fatal("expected the public host and loopback hosts to be allowed")
	}
	if app.hostAllowed("evil.example") {
		t.Fatal("unexpected host was allowed")
	}
	if app.webAuthnRPID != "hibp.lan" || app.webAuthnOrigin != "https://hibp.lan:8443" {
		t.Fatalf("unexpected WebAuthn config: rpID=%q origin=%q", app.webAuthnRPID, app.webAuthnOrigin)
	}
	for _, host := range []string{"hibp.lan:8443", "localhost:8443", "127.0.0.1:8443"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("host %s: expected 200, got %d", host, resp.StatusCode)
		}
	}
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example:8443"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an unconfigured Host header, got %d", resp.StatusCode)
	}
}

func TestDemoInsecureLANHTTPRequiresOptIn(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cfg := Config{
		Store:         db,
		Version:       "test",
		SSHConfigPath: filepath.Join(t.TempDir(), "missing-config"),
		PublicURL:     "http://192.168.1.50:8011",
		Demo:          true,
	}
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "HIBP_DEMO_ALLOW_INSECURE_HTTP") {
		t.Fatalf("expected demo opt-in error, got %v", err)
	}
	cfg.AllowInsecureHTTP = true
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !app.hostAllowed("192.168.1.50") {
		t.Fatal("expected the configured LAN address to be allowed")
	}
	recorder := httptest.NewRecorder()
	app.setSessionCookie(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), "token", time.Hour)
	cookie := recorder.Result().Cookies()[0]
	if cookie.Name != "hibp_demo_session" || cookie.Secure {
		t.Fatalf("unexpected demo cookie over HTTP: name=%q secure=%v", cookie.Name, cookie.Secure)
	}
	cfg.Demo = false
	if _, err := New(cfg); err == nil {
		t.Fatal("expected non-demo HTTP LAN URL to be rejected")
	}
}

func TestSessionCookieSecureFollowsRequestScheme(t *testing.T) {
	app := &Server{sessionCookie: "hibp_demo_session"}
	check := func(name string, req *http.Request, wantSecure bool) {
		t.Helper()
		recorder := httptest.NewRecorder()
		app.setSessionCookie(recorder, req, "token", time.Hour)
		cookie := recorder.Result().Cookies()[0]
		if cookie.Secure != wantSecure {
			t.Fatalf("%s: expected Secure=%v, got %v", name, wantSecure, cookie.Secure)
		}
	}
	check("plain HTTP", httptest.NewRequest(http.MethodPost, "http://demo.lan:8011/api/v1/auth/login", nil), false)
	httpsReq := httptest.NewRequest(http.MethodPost, "https://demo.lan:8011/api/v1/auth/login", nil)
	httpsReq.TLS = &tls.ConnectionState{}
	check("direct HTTPS", httpsReq, true)
	proxyNets, err := parseTrustedProxyCIDRs([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	app.trustProxy = true
	app.trustedProxyNets = proxyNets
	proxyReq := httptest.NewRequest(http.MethodPost, "http://demo.lan:8011/api/v1/auth/login", nil)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	check("HTTPS proxy", proxyReq, true)
}

func TestTrustedProxyOnlyFromCIDR(t *testing.T) {
	nets, err := parseTrustedProxyCIDRs([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	app := &Server{trustProxy: true, trustedProxyNets: nets}
	trusted := httptest.NewRequest(http.MethodGet, "http://hibp.example/api/v1/status", nil)
	trusted.RemoteAddr = "127.0.0.1:43210"
	trusted.Header.Set("X-Forwarded-Proto", "https")
	if got := app.requestScheme(trusted); got != "https" {
		t.Fatalf("trusted proxy scheme: got %q", got)
	}
	untrusted := httptest.NewRequest(http.MethodGet, "http://hibp.example/api/v1/status", nil)
	untrusted.RemoteAddr = "192.0.2.25:43210"
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	if got := app.requestScheme(untrusted); got != "http" {
		t.Fatalf("untrusted proxy scheme: got %q", got)
	}
}

func TestWebAuthnConfigForPublicHost(t *testing.T) {
	app := &Server{webAuthnRPID: "hibp.lan", webAuthnOrigin: "https://hibp.lan:8443"}
	request := httptest.NewRequest(http.MethodPost, "https://hibp.lan:8443/api/v1/auth/passkey/register/begin", nil)
	request.Host = "hibp.lan:8443"
	request.TLS = &tls.ConnectionState{}
	rpID, origin, err := app.webAuthnConfig(request)
	if err != nil || rpID != "hibp.lan" || origin != "https://hibp.lan:8443" {
		t.Fatalf("unexpected public WebAuthn config: rpID=%q origin=%q err=%v", rpID, origin, err)
	}

	request.TLS = nil
	if _, _, err := app.webAuthnConfig(request); err == nil {
		t.Fatal("expected plain HTTP to be rejected for the public host")
	}

	request.Host = "localhost:8443"
	request.TLS = &tls.ConnectionState{}
	rpID, origin, err = app.webAuthnConfig(request)
	if err != nil || rpID != "localhost" || origin != "https://localhost:8443" {
		t.Fatalf("unexpected localhost WebAuthn config: rpID=%q origin=%q err=%v", rpID, origin, err)
	}

	nets, err := parseTrustedProxyCIDRs([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	app.trustProxy = true
	app.trustedProxyNets = nets
	proxyRequest := httptest.NewRequest(http.MethodPost, "http://hibp.lan:8443/api/v1/auth/passkey/register/begin", nil)
	proxyRequest.Host = "hibp.lan:8443"
	proxyRequest.RemoteAddr = "127.0.0.1:43210"
	proxyRequest.Header.Set("X-Forwarded-Proto", "https")
	rpID, origin, err = app.webAuthnConfig(proxyRequest)
	if err != nil || rpID != "hibp.lan" || origin != "https://hibp.lan:8443" {
		t.Fatalf("unexpected proxied WebAuthn config: rpID=%q origin=%q err=%v", rpID, origin, err)
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

func TestNonDemoIgnoresDemoSessionHeader(t *testing.T) {
	ts, _ := testServer(t)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/hosts", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The seeded test session uses this raw token, but only the demo build may
	// authenticate from the demo header.
	req.Header.Set(demoSessionHeader, "test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without the session cookie, got %d", resp.StatusCode)
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

func TestHostAPTUpgradeMode(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"apt01","address":"10.0.0.30","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","apt_upgrade_mode":"full"}`
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
	if host.APTUpgradeMode != "full" {
		t.Fatalf("expected full mode, got %q", host.APTUpgradeMode)
	}

	// A partial update that omits the mode must preserve it.
	update := `{"name":"apt01","address":"10.0.0.30","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", update)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %d", resp.StatusCode)
	}
	var updated store.Host
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.APTUpgradeMode != "full" {
		t.Fatalf("expected full mode preserved, got %q", updated.APTUpgradeMode)
	}

	invalid := `{"name":"apt01","address":"10.0.0.30","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","apt_upgrade_mode":"dangerous"}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", invalid)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid mode to be rejected, got %d", resp.StatusCode)
	}
}

func TestDeleteHostEndpoint(t *testing.T) {
	ts, db := testServer(t)
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
	if err := db.SaveFacts(host.ID, store.Facts{CollectedAt: "2026-11-12T07:00:00Z", OSPrettyName: "Ubuntu 24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDockerInventory(host.ID,
		[]store.DockerProject{{Name: "web", Status: "running(1)"}},
		[]store.DockerContainer{{ContainerID: "abc", Name: "web-1", Project: "web", State: "running"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDockerProjectCheck(store.DockerProjectCheck{HostID: host.ID, Project: "web", Status: "update-available"}); err != nil {
		t.Fatal(err)
	}

	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", "")
	var deleted struct {
		Deleted bool `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&deleted); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !deleted.Deleted {
		t.Fatalf("delete failed: %d %+v", resp.StatusCode, deleted)
	}

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected deleted host to be missing, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected second delete to be 404, got %d", resp.StatusCode)
	}
	projects, containers, err := db.GetDockerInventory(host.ID)
	if err != nil || len(projects) != 0 || len(containers) != 0 {
		t.Fatalf("docker inventory not cascaded: %+v %+v %v", projects, containers, err)
	}
	checks, err := db.ListDockerProjectChecks(host.ID)
	if err != nil || len(checks) != 0 {
		t.Fatalf("docker checks not cascaded: %+v %v", checks, err)
	}
	audit, err := db.ListAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range audit {
		if entry.Action == "delete" && entry.EntityType == "host" && entry.EntityID == host.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("host delete audit entry missing")
	}
}

func TestProxyJumpHostEndpoint(t *testing.T) {
	ts, db := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","proxy_jump_address":"jump.example.com","proxy_jump_port":2200,"proxy_jump_username":"jumpuser","proxy_jump_key_path":"/home/ops/.ssh/jump_key"}`
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
	if host.ProxyJump == nil || host.ProxyJump.Address != "jump.example.com" || host.ProxyJump.Port != 2200 {
		t.Fatalf("unexpected proxy jump: %+v", host.ProxyJump)
	}
	if err := db.SetProxyJumpKeyAs("test", host.ID, "ssh-ed25519", "SHA256:jump"); err != nil {
		t.Fatal(err)
	}

	update := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","proxy_jump_address":"jump.example.com","proxy_jump_port":2200,"proxy_jump_username":"jumpuser","proxy_jump_key_path":"/home/ops/.ssh/jump_key"}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", update)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("update failed: %d %s", resp.StatusCode, data)
	}
	var preserved store.Host
	if err := json.NewDecoder(resp.Body).Decode(&preserved); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if preserved.ProxyJump == nil || preserved.ProxyJump.KeyType != "ssh-ed25519" || preserved.ProxyJump.Fingerprint != "SHA256:jump" {
		t.Fatalf("jump key was not preserved: %+v", preserved.ProxyJump)
	}

	update = `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","proxy_jump_address":"other-jump.example.com","proxy_jump_port":22,"proxy_jump_username":"jumpuser"}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", update)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("jump change failed: %d %s", resp.StatusCode, data)
	}
	var changed store.Host
	if err := json.NewDecoder(resp.Body).Decode(&changed); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if changed.ProxyJump == nil || changed.ProxyJump.Address != "other-jump.example.com" || changed.ProxyJump.KeyType != "" || changed.ProxyJump.Fingerprint != "" {
		t.Fatalf("jump key should be cleared on address change: %+v", changed.ProxyJump)
	}

	invalid := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","proxy_jump_address":"jump.example.com","proxy_jump_port":70000,"proxy_jump_username":"jumpuser"}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", invalid)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid jump port rejection, got %d", resp.StatusCode)
	}

	direct := `{"name":"direct01","address":"10.0.0.20","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", direct)
	var directHost store.Host
	if err := json.NewDecoder(resp.Body).Decode(&directHost); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+directHost.ID+"/trust-jump-key", "test-token", `{"key_type":"ssh-ed25519","fingerprint":"SHA256:jump"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected no-jump rejection, got %d", resp.StatusCode)
	}
}

func TestListSSHKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte("public key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_rsa.pub"), []byte("public key"), 0o644); err != nil {
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
	for _, entry := range result.Entries {
		if strings.HasSuffix(strings.ToLower(entry.Name), ".pub") {
			t.Fatalf("public key was not filtered: %+v", result.Entries)
		}
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

func TestCSVUpdatePreservesUnmentionedFields(t *testing.T) {
	ts, _ := testServer(t)
	create := `{"name":"keepme","address":"10.9.9.9","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519","group_name":"prod","tags":"a,b","cmdb_ci_id":"CI-1"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", create)
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create failed: %d %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()

	payload, _ := json.Marshal(map[string]any{
		"csv":              "name,address,port,username,auth_type,key_path\nkeepme,10.9.9.9,22,ubuntu,key,/home/ops/.ssh/id_ed25519\n",
		"commit":           true,
		"duplicate_policy": "update",
	})
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token", string(payload))
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("import failed: %d %s", resp.StatusCode, data)
	}
	var result importResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if result.Updated != 1 {
		t.Fatalf("expected one updated host, got %+v", result)
	}

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("get host failed: %d", resp.StatusCode)
	}
	var updated store.Host
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if updated.GroupName != "prod" || updated.Tags != "a,b" || updated.CMDBCIID != "CI-1" {
		t.Fatalf("CSV update erased unmentioned fields: %+v", updated)
	}
	if updated.Status != host.Status {
		t.Fatalf("CSV update changed status from %q to %q", host.Status, updated.Status)
	}
}

func TestCSVUpdatePreservesPasswordAuthWhenAuthColumnAbsent(t *testing.T) {
	ts, _ := testServer(t)
	create := `{"name":"legacy","address":"10.9.9.10","port":22,"username":"root","auth_type":"password"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", create)
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create failed: %d %s", resp.StatusCode, data)
	}
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()

	payload, _ := json.Marshal(map[string]any{
		"csv":              "name,address,port,username\nlegacy,10.9.9.10,22,root\n",
		"commit":           true,
		"duplicate_policy": "update",
	})
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token", string(payload))
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("import failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID, "test-token", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("get host failed: %d", resp.StatusCode)
	}
	var updated store.Host
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if updated.AuthType != "password" {
		t.Fatalf("CSV update changed auth_type to %q", updated.AuthType)
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

func TestPatchResponseIncludesRebootOutcome(t *testing.T) {
	payload, err := json.Marshal(patchResponse{
		Result:          helper.Result{Action: "apply", OK: true, ExitCode: 0, Output: "patched"},
		RebootRequired:  true,
		RebootRequested: true,
		RebootOutput:    "reboot requested",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, expected := range []string{`"action":"apply"`, `"ok":true`, `"output":"patched"`, `"reboot_required":true`, `"reboot_requested":true`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("patch response %s does not contain %s", text, expected)
		}
	}
}

func TestPreviewHashIsStableAndOrderIndependent(t *testing.T) {
	first := helper.PreviewResult{
		PackageManager: "apt",
		Packages: []helper.PackageChange{
			{Name: "b", Action: "install", NewVersion: "2.0"},
			{Name: "a", Action: "upgrade", OldVersion: "1.0", NewVersion: "1.1"},
		},
	}
	second := helper.PreviewResult{
		PackageManager: "apt",
		Packages: []helper.PackageChange{
			{Name: "a", Action: "upgrade", OldVersion: "1.0", NewVersion: "1.1"},
			{Name: "b", Action: "install", NewVersion: "2.0"},
		},
	}
	if previewHash(first) != previewHash(second) {
		t.Fatal("preview hash changed when package order changed")
	}
	second.Packages[1].NewVersion = "2.1"
	if previewHash(first) == previewHash(second) {
		t.Fatal("preview hash did not change when package version changed")
	}
}

func TestPatchApplyRequiresPreviewHash(t *testing.T) {
	ts, _ := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
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
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/patch", "test-token", `{"dry_run":false,"confirm":"apply"}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "preview_required") {
		t.Fatalf("expected preview_required, got %d %s", resp.StatusCode, data)
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

func TestStoreFactsFromHelperIncludesCleanup(t *testing.T) {
	facts := storeFactsFromHelper(helper.Facts{
		PackageManager: "apt", PendingUpdates: 4, OrphanedPackages: 3, CleanupSupported: true,
	})
	if facts.PendingUpdates != 4 || facts.OrphanedPackages != 3 || !facts.CleanupSupported {
		t.Fatalf("cleanup facts were not mapped: %+v", facts)
	}
}

func TestRebootProtectsController(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "controller", Address: "127.0.0.1", Port: 1, Username: "root",
		AuthType: "key", KeyPath: "/nonexistent/hibp-test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !app.isControllerHost(host) {
		t.Fatal("expected loopback host to be treated as the controller")
	}

	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/reboot", "test-token", `{"confirm":"reboot"}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "controller_protected") {
		t.Fatalf("expected controller protection, got %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/reboot", "test-token", `{"confirm":"reboot","allow_controller":true}`)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "controller_protected") {
		t.Fatalf("explicit per-host approval was still rejected: %d %s", resp.StatusCode, body)
	}
}

func TestPostPatchRebootSkipsController(t *testing.T) {
	_, _, app := testServerWithApp(t, true)
	required, requested, _, err := app.checkAndReboot(context.Background(), store.Host{
		Name: "controller", Address: "127.0.0.1", Port: 1,
	}, "", "")
	if err == nil || required || requested {
		t.Fatalf("expected controller reboot refusal, got required=%v requested=%v err=%v", required, requested, err)
	}
}

func TestControllerNamesIncludeLoopbackAndHostIdentity(t *testing.T) {
	names := controllerNames()
	for _, value := range []string{"localhost", "127.0.0.1", "::1"} {
		if !names[value] {
			t.Fatalf("controller names missing %q: %v", value, names)
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if !names[controllerName(hostname)] {
		t.Fatalf("controller names missing local hostname %q", hostname)
	}
}

func TestCleanupRequiresConfirmation(t *testing.T) {
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
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/cleanup", "test-token", `{"dry_run":false}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(data), "confirm") {
		t.Fatalf("expected cleanup confirmation error, got %d %s", resp.StatusCode, data)
	}
}

func TestCleanupRejectsBusyHost(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !app.tryLockHost(host.ID) {
		t.Fatal("host was already locked")
	}
	defer app.unlockHost(host.ID)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/cleanup", "test-token", `{"dry_run":true}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "host_busy") {
		t.Fatalf("expected host_busy conflict, got %d %s", resp.StatusCode, body)
	}
}

func TestCleanupProtectsController(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "controller", Address: "127.0.0.1", Port: 1, Username: "root",
		AuthType: "key", KeyPath: "/nonexistent/hibp-test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !app.isControllerHost(host) {
		t.Fatal("expected loopback host to be treated as the controller")
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/cleanup", "test-token", `{"dry_run":false,"confirm":"cleanup"}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "controller_protected") {
		t.Fatalf("expected controller cleanup protection, got %d %s", resp.StatusCode, body)
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
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", `{"scope":"fleet","settings":{"collector.metrics_interval":"1m","metrics.retention_days":"14","monitor.service_baseline.exclude":"packagekit.service, systemd-timedated.service, check-mk-agent@*"}}`)
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
	if payload.Resolved["monitor.service_baseline.exclude"] != "packagekit.service, systemd-timedated.service, check-mk-agent@*" {
		t.Fatalf("unexpected fleet baseline exclusions: %#v", payload.Resolved)
	}
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", `{"scope":"fleet","settings":{"collector.metrics_interval":"2s","metrics.retention_days":"99"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("expected invalid interval rejection, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", `{"scope":"fleet","settings":{"monitor.service_baseline.exclude":"bad;unit"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("expected invalid fleet baseline unit rejection, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/settings", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("get settings after rejected update failed: %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if payload.Resolved["collector.metrics_interval"] != "1m" || payload.Resolved["metrics.retention_days"] != "14" {
		t.Fatalf("rejected settings update was partially applied: %#v", payload.Resolved)
	}
	if payload.Resolved["monitor.service_baseline.exclude"] != "packagekit.service, systemd-timedated.service, check-mk-agent@*" {
		t.Fatalf("rejected settings update changed fleet baseline exclusions: %#v", payload.Resolved)
	}
}

func TestSNMPCommunityMaskedAndPreserved(t *testing.T) {
	ts, db := testServer(t)
	resp := request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"fleet","settings":{"snmp.community":"secret-community"}}`)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("save SNMP community failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	if value, err := db.GetSetting("fleet", "snmp.community"); err != nil || value != "secret-community" {
		t.Fatalf("stored community: %q %v", value, err)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/settings", "test-token", "")
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(raw), "secret-community") {
		t.Fatalf("SNMP community leaked through settings API: %s", raw)
	}
	if !strings.Contains(string(raw), `"snmp.community":"********"`) {
		t.Fatalf("masked SNMP community missing from settings API: %s", raw)
	}
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"fleet","settings":{"snmp.community":"********"}}`)
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("masked update failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if value, err := db.GetSetting("fleet", "snmp.community"); err != nil || value != "secret-community" {
		t.Fatalf("masked update changed community: %q %v", value, err)
	}
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"fleet","settings":{"snmp.community":""}}`)
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("clear community failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if _, err := db.GetSetting("fleet", "snmp.community"); err == nil {
		t.Fatal("expected SNMP community to be cleared")
	}
}

func TestHostTargetProxyJump(t *testing.T) {
	_, _, app := testServerWithApp(t, true)
	host := store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
		ProxyJump: &store.ProxyJump{Address: "jump.example.com", Port: 2200, Username: "jumpuser",
			KeyType: "ssh-ed25519", Fingerprint: "SHA256:jump"},
	}
	target := app.hostTarget(host, "")
	if target.ProxyJump == nil || target.ProxyJump.Address != "jump.example.com" ||
		target.ProxyJump.Port != 2200 || target.ProxyJump.Username != "jumpuser" ||
		target.ProxyJump.KeyPath != host.KeyPath || target.ProxyJump.Password != "" {
		t.Fatalf("unexpected key-auth jump target: %+v", target.ProxyJump)
	}
	if target.ProxyJump.HostKey == nil || target.ProxyJump.HostKey.Fingerprint != "SHA256:jump" {
		t.Fatalf("missing jump host key: %+v", target.ProxyJump.HostKey)
	}

	passwordHost := host
	passwordHost.AuthType = "password"
	passwordTarget := app.hostTarget(passwordHost, "secret")
	if passwordTarget.ProxyJump.KeyPath != "" || passwordTarget.ProxyJump.Password != "secret" {
		t.Fatalf("unexpected password-auth jump target: %+v", passwordTarget.ProxyJump)
	}

	explicitKeyHost := passwordHost
	explicitKeyHost.ProxyJump = &store.ProxyJump{Address: "jump.example.com", Port: 22, Username: "jumpuser", KeyPath: "/home/ops/.ssh/jump_key"}
	explicitKeyTarget := app.hostTarget(explicitKeyHost, "secret")
	if explicitKeyTarget.ProxyJump.KeyPath != "/home/ops/.ssh/jump_key" || explicitKeyTarget.ProxyJump.Password != "" {
		t.Fatalf("unexpected explicit jump key target: %+v", explicitKeyTarget.ProxyJump)
	}
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
	if err := db.SaveDockerProjectCheck(store.DockerProjectCheck{
		HostID: host.ID, Project: "web", Status: "update-available", Summary: "Update available: frontend",
	}); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details", "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("details failed: %d %s", resp.StatusCode, data)
	}
	var details struct {
		Host       store.Host                 `json:"host"`
		SystemInfo map[string]any             `json:"system_info"`
		Metrics    []store.MetricSample       `json:"metrics"`
		Projects   []store.DockerProject      `json:"docker_projects"`
		Containers []store.DockerContainer    `json:"docker_containers"`
		Checks     []store.DockerProjectCheck `json:"docker_checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		t.Fatal(err)
	}
	if details.SystemInfo["hostname"] != "web01" || len(details.Metrics) != 1 || len(details.Projects) != 1 || len(details.Containers) != 1 {
		t.Fatalf("unexpected details: %+v", details)
	}
	if len(details.Checks) != 1 || details.Checks[0].Status != "update-available" {
		t.Fatalf("unexpected docker checks: %+v", details.Checks)
	}
	if details.Host.DockerProjectCount != 1 || details.Host.DockerContainerCount != 1 {
		t.Fatalf("unexpected docker counts: %+v", details.Host)
	}
}

func TestHostDetailsIncludesSettingInheritance(t *testing.T) {
	ts, _ := testServer(t)
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

	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"fleet","settings":{"collector.metrics_interval":"1m"}}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("fleet settings failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	type details struct {
		Settings          map[string]string `json:"settings"`
		HostSettings      map[string]string `json:"host_settings"`
		InheritedSettings map[string]string `json:"inherited_settings"`
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("details failed: %d", resp.StatusCode)
	}
	var first details
	if err := json.NewDecoder(resp.Body).Decode(&first); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if first.Settings["collector.metrics_interval"] != "1m" || first.InheritedSettings["collector.metrics_interval"] != "1m" {
		t.Fatalf("unexpected inherited settings: %+v", first)
	}
	if _, ok := first.HostSettings["collector.metrics_interval"]; ok {
		t.Fatal("host unexpectedly had an override before it was saved")
	}

	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token",
		`{"scope":"host","host_id":"`+host.ID+`","settings":{"collector.metrics_interval":"2m"}}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("host settings failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("details after override failed: %d", resp.StatusCode)
	}
	var second details
	if err := json.NewDecoder(resp.Body).Decode(&second); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()
	if second.Settings["collector.metrics_interval"] != "2m" ||
		second.HostSettings["collector.metrics_interval"] != "2m" ||
		second.InheritedSettings["collector.metrics_interval"] != "1m" {
		t.Fatalf("unexpected override/inherited split: %+v", second)
	}
}

func TestHostDetailsMetricsRange(t *testing.T) {
	ts, db := testServer(t)
	body := `{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token", body)
	defer resp.Body.Close()
	var host store.Host
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := db.SaveMetrics(host.ID, store.MetricSample{
		CollectedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), CPUPercent: 20,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveMetrics(host.ID, store.MetricSample{
		CollectedAt: now.Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano), CPUPercent: 80,
	}); err != nil {
		t.Fatal(err)
	}
	type details struct {
		Metrics     []store.MetricSample `json:"metrics"`
		MetricsDays int                  `json:"metrics_days"`
	}
	fetch := func(query string) details {
		resp := request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details"+query, "test-token", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			t.Fatalf("details%s failed: %d %s", query, resp.StatusCode, data)
		}
		var payload details
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}
	defaults := fetch("")
	if defaults.MetricsDays != 30 || len(defaults.Metrics) != 1 || defaults.Metrics[0].CPUPercent != 20 {
		t.Fatalf("unexpected default range: %+v", defaults)
	}
	wide := fetch("?metrics_days=90")
	if wide.MetricsDays != 90 || len(wide.Metrics) != 2 {
		t.Fatalf("unexpected 90-day range: %+v", wide)
	}
	for _, query := range []string{"?metrics_days=0", "?metrics_days=abc", "?metrics_days=3651"} {
		resp := request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/details"+query, "test-token", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected %s to be rejected, got %d", query, resp.StatusCode)
		}
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
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/update-selected", "test-token", `{"projects":[],"confirm":"update"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected empty selection rejection, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/update-selected", "test-token", `{"projects":["bad project"],"confirm":"update"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid selected project rejection, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/update-selected", "test-token", `{"projects":["web"],"confirm":"update"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected unknown selected project rejection, got %d", resp.StatusCode)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/check-all", "test-token", ``)
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatalf("check-all route is not registered: %d", resp.StatusCode)
	}
}

func TestSudoClassifierIgnoresPackageManagerAuthOutput(t *testing.T) {
	output := "Err:1 https://repo.example.com stable InRelease\n  401 Unauthorized\nAuthentication failed for repository\n"
	if looksLikeSudoAuthFailure(output) || looksLikeSudoPasswordInvalid(output) {
		t.Fatal("package-manager authentication output was misclassified as sudo")
	}
	if !looksLikeSudoAuthFailure("sudo: a password is required") {
		t.Fatal("sudo password prompt was not recognized")
	}
	if !looksLikeSudoPasswordInvalid("sudo: Authentication failed, try again.") {
		t.Fatal("sudo rejected password was not recognized")
	}
}

func TestDockerActionsRespectHostLock(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !app.tryLockHost(host.ID) {
		t.Fatal("test could not lock host")
	}
	defer app.unlockHost(host.ID)

	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/check", "test-token", `{"project":"web"}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "host_busy") {
		t.Fatalf("expected docker check host_busy, got %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/docker/apply", "test-token", `{"project":"web","confirm":"apply"}`)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "host_busy") {
		t.Fatalf("expected docker apply host_busy, got %d %s", resp.StatusCode, body)
	}
}

func TestDockerCheckStatusAndPersistence(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}

	status, summary := dockerCheckStatus(helper.DockerCheckResult{OK: true, Services: []helper.DockerServiceUpdate{
		{Service: "frontend", Status: "new-image"},
		{Service: "db", Status: "unchanged"},
	}})
	if status != "update-available" || summary != "Update available: frontend" {
		t.Fatalf("unexpected update status: %s %s", status, summary)
	}
	status, summary = dockerCheckStatus(helper.DockerCheckResult{OK: true})
	if status != "up-to-date" || summary != "Up to date" {
		t.Fatalf("unexpected up-to-date status: %s %s", status, summary)
	}
	status, summary = dockerCheckStatus(helper.DockerCheckResult{OK: false, Error: "pull failed"})
	if status != "failed" || summary != "pull failed" {
		t.Fatalf("unexpected failed status: %s %s", status, summary)
	}

	app.saveDockerProjectUpdate(host.ID, helper.DockerProjectUpdateResult{
		Name: "web", Action: "updated", OK: true,
		Check: &helper.DockerCheckResult{OK: true, Services: []helper.DockerServiceUpdate{{Service: "frontend", Status: "new-image"}}},
	})
	checks, err := db.ListDockerProjectChecks(host.ID)
	if err != nil || len(checks) != 1 {
		t.Fatalf("docker checks: %+v %v", checks, err)
	}
	if checks[0].Status != "updated" || checks[0].Summary != "Recreated: frontend" {
		t.Fatalf("updated status not persisted: %+v", checks[0])
	}

	app.saveDockerProjectUpdate(host.ID, helper.DockerProjectUpdateResult{Name: "web", Action: "no-change", OK: true})
	checks, _ = db.ListDockerProjectChecks(host.ID)
	if checks[0].Status != "up-to-date" || checks[0].Summary != "Up to date" {
		t.Fatalf("no-change status not persisted: %+v", checks[0])
	}

	app.saveDockerProjectUpdate(host.ID, helper.DockerProjectUpdateResult{Name: "web", Action: "failed", Error: "apply failed"})
	checks, _ = db.ListDockerProjectChecks(host.ID)
	if checks[0].Status != "failed" || checks[0].Error != "apply failed" {
		t.Fatalf("failed status not persisted: %+v", checks[0])
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
