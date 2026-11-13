package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
)

func addTestPasskey(t *testing.T, db *store.Store, userID, name string) store.Passkey {
	t.Helper()
	credentialJSON, err := json.Marshal(webauthn.Credential{ID: []byte(name), PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	passkey, err := db.AddPasskey(userID, []byte(name), string(credentialJSON), 0, name)
	if err != nil {
		t.Fatal(err)
	}
	return passkey
}

func TestMFAManagementPreventsRemovingLastFactor(t *testing.T) {
	ts, db := testServer(t)
	user, err := db.GetUserByUsername("test")
	if err != nil {
		t.Fatal(err)
	}
	passkey := addTestPasskey(t, db, user.ID, "Laptop")

	resp := request(t, http.MethodGet, ts.URL+"/api/v1/auth/mfa", "test-token", "")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Laptop") {
		t.Fatalf("list MFA failed: %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/auth/passkeys/"+passkey.ID, "test-token", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected last-factor removal to be rejected, got %d", resp.StatusCode)
	}

	if err := db.EnableTOTP(user.ID, "JBSWY3DPEHPK3PXP", 0); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/auth/passkeys/"+passkey.ID, "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected passkey removal with TOTP enabled, got %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/auth/totp", "test-token", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected TOTP removal to be rejected without passkeys, got %d", resp.StatusCode)
	}

	addTestPasskey(t, db, user.ID, "YubiKey")
	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/auth/totp", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected TOTP removal with a passkey, got %d %s", resp.StatusCode, body)
	}
	loaded, err := db.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TOTPEnabled {
		t.Fatal("TOTP remained enabled after removal")
	}
}

func TestPasskeyOnlyAccountCannotEnrollTOTPWithPassword(t *testing.T) {
	ts, db := testServer(t)
	user, err := db.GetUserByUsername("test")
	if err != nil {
		t.Fatal(err)
	}
	addTestPasskey(t, db, user.ID, "Laptop")

	// Obtain a password-only (MFA pending) session.
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/login", "",
		`{"username":"test","password":"test-password-123"}`)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("password login failed: %d %s", resp.StatusCode, body)
	}
	pending := findSessionCookie(t, resp).Value
	resp.Body.Close()

	// The normal enrollment endpoint must refuse to start.
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/auth/totp/begin", pending, `{}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("passkey-only account started TOTP enrollment: %d %s", resp.StatusCode, body)
	}

	// Even if a pending secret already exists (for example from an older build
	// or a race), verification must not enable it without an MFA-verified
	// session.
	const secret = "JBSWY3DPEHPK3PXP"
	if err := db.SetTOTPPendingSecret(user.ID, secret); err != nil {
		t.Fatal(err)
	}
	code, _, err := auth.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/auth/totp/verify", pending,
		fmt.Sprintf(`{"code":%q}`, code))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("passkey-only account enabled TOTP from a password-only session: %d %s", resp.StatusCode, body)
	}
	loaded, err := db.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TOTPEnabled {
		t.Fatal("TOTP was enabled on a passkey-only account without MFA")
	}
}

func TestMFAVerifiedSessionCanAddTOTPWithPasskey(t *testing.T) {
	ts, db := testServer(t)
	user, err := db.GetUserByUsername("test")
	if err != nil {
		t.Fatal(err)
	}
	addTestPasskey(t, db, user.ID, "Laptop")

	resp := request(t, http.MethodPost, ts.URL+"/api/v1/auth/totp/begin", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("MFA-verified session could not start TOTP enrollment: %d %s", resp.StatusCode, body)
	}
	var totp struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&totp); err != nil {
		resp.Body.Close()
		t.Fatal(err)
	}
	resp.Body.Close()

	code, _, err := auth.TOTPCode(totp.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/auth/totp/verify", "test-token",
		fmt.Sprintf(`{"code":%q}`, code))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MFA-verified session could not enable TOTP: %d %s", resp.StatusCode, body)
	}
	loaded, err := db.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.TOTPEnabled {
		t.Fatal("TOTP was not enabled for an MFA-verified session")
	}
}

func TestHostAndImportAuditUseAuthenticatedActor(t *testing.T) {
	ts, db := testServer(t)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token",
		`{"name":"web01","address":"10.0.0.10","port":22,"username":"ubuntu","auth_type":"key","key_path":"/home/ops/.ssh/id_ed25519"}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create host failed: %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/import", "test-token",
		`{"csv":"name,address,port,username,auth_type,key_path\nweb02,10.0.0.11,22,ubuntu,key,/home/ops/.ssh/id_ed25519\n","commit":true,"duplicate_policy":"error"}`)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import failed: %d %s", resp.StatusCode, body)
	}

	entries, err := db.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	actors := map[string]string{}
	for _, entry := range entries {
		if entry.Action == "create" && entry.EntityType == "host" {
			actors[entry.EntityID] = entry.Actor
		}
	}
	if len(actors) != 2 {
		t.Fatalf("expected two create audit entries, got %+v", actors)
	}
	for hostID, actor := range actors {
		if actor != "test" {
			t.Fatalf("host %s audit actor = %q, want test", hostID, actor)
		}
	}
}

func TestUnsupportedAuthTypesAreRejected(t *testing.T) {
	ts, _ := testServer(t)
	for _, authType := range []string{"agent", "certificate"} {
		resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts", "test-token",
			`{"name":"`+authType+`","address":"10.0.0.20","port":22,"username":"root","auth_type":"`+authType+`"}`)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected %s host creation to be rejected, got %d %s", authType, resp.StatusCode, body)
		}
	}
}

func TestFailedManualPatchIsAudited(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/patch", "test-token", `{"dry_run":true}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected patch to fail without a trusted key, got %d %s", resp.StatusCode, body)
	}
	entries, err := db.ListAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "patch-check-failed" && entry.EntityID == host.ID && entry.Actor == "test" {
			return
		}
	}
	t.Fatalf("failed patch attempt was not audited: %+v", entries)
}
