package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupUsesConfiguredDirectory(t *testing.T) {
	ts, _ := testServer(t)
	backupDir := filepath.Join(t.TempDir(), "new-backups")
	settings, _ := json.Marshal(map[string]any{
		"scope": "fleet",
		"settings": map[string]string{
			"backup.directory":       backupDir,
			"backup.retention_count": "3",
		},
	})
	resp := request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", string(settings))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save backup settings failed: %d", resp.StatusCode)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/backup", "test-token", `{}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("backup failed: %d %s", resp.StatusCode, data)
	}
	var result struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(result.Path) != backupDir {
		t.Fatalf("backup path %q is not in configured directory %q", result.Path, backupDir)
	}
	for _, path := range []string{result.Path, result.Path + ".meta"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("backup file missing: %s: %v", path, err)
		}
	}

	relative, _ := json.Marshal(map[string]any{
		"scope":    "fleet",
		"settings": map[string]string{"backup.directory": "relative/backups"},
	})
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/settings", "test-token", string(relative))
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected relative backup directory to be rejected, got %d %s", resp.StatusCode, data)
	}
}
