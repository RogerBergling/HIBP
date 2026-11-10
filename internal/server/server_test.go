package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RogerBergling/hibp/internal/store"
)

func testServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app, err := New(Config{Store: db, Token: "test-token", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(app.Handler())
	t.Cleanup(ts.Close)
	return ts, db
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
		req.Header.Set("Authorization", "Bearer "+token)
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
	req.Header.Set("Authorization", "Bearer test-token")
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
