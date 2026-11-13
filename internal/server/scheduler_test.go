package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

func TestScheduleCRUDAndValidation(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", GroupName: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	base := ts.URL

	invalid := `{"name":"Bad","mode":"apply","enabled":true,"cron":"not a cron","timezone":"UTC","assignments":[{"scope":"fleet"}]}`
	resp := request(t, http.MethodPost, base+"/api/v1/schedules", "test-token", invalid)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected cron validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	noAssignments := `{"name":"Bad","mode":"apply","enabled":true,"cron":"0 3 * * *","timezone":"UTC","assignments":[]}`
	resp = request(t, http.MethodPost, base+"/api/v1/schedules", "test-token", noAssignments)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected assignment validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	badTimezone := `{"name":"Bad","mode":"apply","enabled":true,"cron":"0 3 * * *","timezone":"Mars/Olympus","assignments":[{"scope":"fleet"}]}`
	resp = request(t, http.MethodPost, base+"/api/v1/schedules", "test-token", badTimezone)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected timezone validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	payload := scheduleRequest{
		Name: "Nightly patches", Mode: "apply", Enabled: true, Cron: "0 3 * * *",
		Timezone: "Europe/Stockholm", WindowMinutes: 120, JitterSeconds: 60,
		MaxConcurrency: 3, Retries: 2, RebootAfterApply: true, Notify: "failures",
		Assignments: []store.ScheduleAssignment{
			{Scope: "host", Target: host.ID},
			{Scope: "group", Target: "web"},
		},
	}
	body, _ := json.Marshal(payload)
	resp = request(t, http.MethodPost, base+"/api/v1/schedules", "test-token", string(body))
	responseBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create schedule failed: %d %s", resp.StatusCode, responseBody)
	}
	var created store.Schedule
	if err := json.Unmarshal(responseBody, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.NextRunAt == "" || len(created.Assignments) != 2 {
		t.Fatalf("unexpected schedule: %+v", created)
	}
	if created.Retries != 2 {
		t.Fatalf("created retries = %d, want 2", created.Retries)
	}
	if !created.RebootAfterApply {
		t.Fatalf("created reboot_after_apply = false, want true")
	}

	resp = request(t, http.MethodGet, base+"/api/v1/schedules", "test-token", "")
	responseBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(responseBody), "Nightly patches") {
		t.Fatalf("list schedules failed: %d %s", resp.StatusCode, responseBody)
	}

	payload.Name = "Nightly patches updated"
	payload.Enabled = false
	payload.Assignments = []store.ScheduleAssignment{{Scope: "fleet"}}
	body, _ = json.Marshal(payload)
	resp = request(t, http.MethodPut, base+"/api/v1/schedules/"+created.ID, "test-token", string(body))
	responseBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update schedule failed: %d %s", resp.StatusCode, responseBody)
	}
	var updated store.Schedule
	if err := json.Unmarshal(responseBody, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != payload.Name || updated.Enabled || len(updated.Assignments) != 1 || updated.Assignments[0].Scope != "fleet" {
		t.Fatalf("unexpected updated schedule: %+v", updated)
	}

	resp = request(t, http.MethodPost, base+"/api/v1/schedules/"+created.ID+"/run", "test-token", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected disabled schedule run rejection, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodDelete, base+"/api/v1/schedules/"+created.ID, "test-token", "")
	responseBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete schedule failed: %d %s", resp.StatusCode, responseBody)
	}

	resp = request(t, http.MethodGet, base+"/api/v1/runs?limit=10", "test-token", "")
	responseBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(responseBody), `"runs"`) {
		t.Fatalf("list runs failed: %d %s", resp.StatusCode, responseBody)
	}
}

func TestCheckScheduleIgnoresRebootAfterApply(t *testing.T) {
	_, _, app := testServerWithApp(t, true)
	schedule, err := app.validateScheduleRequest("", scheduleRequest{
		Name: "Check only", Mode: "check", Cron: "0 3 * * *", Timezone: "UTC",
		RebootAfterApply: true,
		Assignments:      []store.ScheduleAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if schedule.RebootAfterApply {
		t.Fatal("check-only schedule must not enable reboot_after_apply")
	}
}

func TestDueScheduleOccurrence(t *testing.T) {
	location, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	lastRun := time.Date(2026, 11, 11, 3, 0, 0, 0, location)
	schedule := store.Schedule{
		Cron: "0 3 * * *", Timezone: "UTC", WindowMinutes: 120,
		LastRunAt: lastRun.Format(time.RFC3339Nano),
	}
	due, run, skipped := dueScheduleOccurrence(schedule, time.Date(2026, 11, 12, 3, 30, 0, 0, location))
	if !run || due.Hour() != 3 || !skipped.IsZero() {
		t.Fatalf("expected due occurrence, got due=%s run=%v skipped=%s", due, run, skipped)
	}

	due, run, skipped = dueScheduleOccurrence(schedule, time.Date(2026, 11, 12, 6, 0, 0, 0, location))
	if run || !due.IsZero() || skipped.Hour() != 3 {
		t.Fatalf("expected skipped occurrence, got due=%s run=%v skipped=%s", due, run, skipped)
	}

	schedule.RunIfMissed = true
	due, run, _ = dueScheduleOccurrence(schedule, time.Date(2026, 11, 12, 6, 0, 0, 0, location))
	if !run || due.Hour() != 3 {
		t.Fatalf("expected missed run, got due=%s run=%v", due, run)
	}
}

func TestScheduleRunSkipsHostsWithoutTrustedKey(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	schedule, err := db.CreateSchedule(store.Schedule{
		Name: "Canary check", Mode: "check", Enabled: true, Cron: "0 3 * * *",
		Timezone: "UTC", WindowMinutes: 120, MaxConcurrency: 3, Notify: "never",
		Assignments: []store.ScheduleAssignment{{Scope: "host", Target: host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.runSchedule(context.Background(), schedule, time.Now().UTC(), true)
	loaded, err := db.GetSchedule(schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastStatus != "skipped" || !strings.Contains(loaded.LastSummary, "no eligible") {
		t.Fatalf("unexpected schedule result: %+v", loaded)
	}
}

func TestBackupToDirectoryUsesTimestampedName(t *testing.T) {
	ts, _ := testServer(t)
	dir := t.TempDir()
	body, _ := json.Marshal(map[string]string{"path": dir})
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/backup", "test-token", string(body))
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
	if !strings.HasSuffix(result.Path, ".bac") || !strings.HasPrefix(filepath.Base(result.Path), "hibp-") {
		t.Fatalf("unexpected backup path: %s", result.Path)
	}
	for _, path := range []string{result.Path, result.Path + ".meta"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("backup file missing: %s: %v", path, err)
		}
	}
}

func TestScheduleRunSkipsHostWithOperationLock(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveHostKey(store.HostKey{HostID: host.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:test"}); err != nil {
		t.Fatal(err)
	}
	schedule, err := db.CreateSchedule(store.Schedule{
		Name: "Locked canary", Mode: "check", Enabled: true, Cron: "0 3 * * *",
		Timezone: "UTC", WindowMinutes: 120, MaxConcurrency: 1, Notify: "never",
		Assignments: []store.ScheduleAssignment{{Scope: "host", Target: host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !app.tryLockHost(host.ID) {
		t.Fatal("test could not lock host")
	}
	defer app.unlockHost(host.ID)
	app.runSchedule(context.Background(), schedule, time.Now().UTC(), true)
	loaded, err := db.GetSchedule(schedule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(loaded.LastSummary, "1 skipped") {
		t.Fatalf("expected busy host to be skipped, got %+v", loaded)
	}
	runs, err := db.ListRuns(10, schedule.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 0 {
		t.Fatalf("busy host should not start a run, got %+v", runs)
	}
}

func TestRebootRequiredFromHelperOutput(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		want    bool
		wantErr bool
	}{
		{name: "required", output: `{"action":"reboot-check","ok":true,"exit_code":0,"output":"reboot required"}`, want: true},
		{name: "not required", output: `{"action":"reboot-check","ok":true,"exit_code":0,"output":"no reboot required"}`, want: false},
		{name: "helper error", output: `{"action":"reboot-check","ok":false,"exit_code":0,"error":"boom"}`, wantErr: true},
		{name: "unexpected text", output: `{"action":"reboot-check","ok":true,"exit_code":0,"output":"maybe"}`, wantErr: true},
		{name: "invalid json", output: `reboot required`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rebootRequiredFromHelperOutput(tc.output)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v, %v; want %v, nil", got, err, tc.want)
			}
		})
	}
}

func TestManualPatchRejectsBusyHost(t *testing.T) {
	ts, db, server := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !server.tryLockHost(host.ID) {
		t.Fatal("host was already locked")
	}
	defer server.unlockHost(host.ID)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/patch", "test-token", `{"dry_run":true}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "host_busy") {
		t.Fatalf("expected host_busy conflict, got %d %s", resp.StatusCode, body)
	}
}
