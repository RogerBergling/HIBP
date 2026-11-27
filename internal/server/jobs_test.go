package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

func TestJobAPIRequiresReviewedPreviewAndRejectsDuplicates(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHostKey(store.HostKey{
		HostID: host.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:test",
	}); err != nil {
		t.Fatal(err)
	}

	resp := request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"patch-apply","host_ids":["`+host.ID+`"],"confirm":"apply"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected missing preview rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"facts","host_ids":["`+host.ID+`"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected created job, got %d", resp.StatusCode)
	}
	var created struct {
		Job jobView `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Job.Status != store.JobQueued || created.Job.Total != 1 {
		t.Fatalf("unexpected job: %+v", created.Job)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"facts","host_ids":["`+host.ID+`"]}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected duplicate active-host rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/jobs", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected job list, got %d", resp.StatusCode)
	}
	var listed struct {
		Jobs []jobView `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(listed.Jobs) != 1 || len(listed.Jobs[0].Targets) != 0 {
		t.Fatalf("expected target-free job summaries, got %+v", listed.Jobs)
	}

	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/jobs/"+created.Job.ID, "test-token", "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected active job delete rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs/"+created.Job.ID+"/cancel", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected cancel acceptance, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/jobs/"+created.Job.ID, "test-token", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected job read, got %d", resp.StatusCode)
	}
	var cancelled struct {
		Job jobView `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cancelled); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if cancelled.Job.Status != store.JobCancelled {
		t.Fatalf("expected queued job to cancel immediately, got %+v", cancelled.Job)
	}
}

func TestRunJobsSkipsIneligiblePasswordHost(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	_ = ts
	host, err := db.CreateHost(store.Host{
		Name: "legacy", Address: "10.0.0.20", Port: 22, Username: "legacy",
		AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := db.CreateJob(store.Job{
		Kind: "facts", Status: store.JobQueued, Actor: "test", Title: "Collect facts",
	}, []store.JobTarget{{HostID: host.ID, HostName: host.Name}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go app.RunJobs(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		updated, err := db.GetJob(job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if updated.Status == store.JobSucceeded || updated.Status == store.JobFailed {
			if updated.Targets[0].Status != store.JobTargetSkipped {
				t.Fatalf("expected skipped target, got %+v", updated.Targets[0])
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
}

func TestPackageUploadCreatesSanitizedJob(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHostKey(store.HostKey{
		HostID: host.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:test",
	}); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("host_ids", `["`+host.ID+`"]`); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("env", `{"WAZUH_MANAGER":"10.0.0.5"}`); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("confirm", "install"); err != nil {
		t.Fatal(err)
	}
	file, err := writer.CreateFormFile("package", "wazuh-agent.deb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("!<arch>\npackage-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/jobs/package", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-token"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected created package job, got %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Job jobView `json:"job"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if created.Job.Package == nil || created.Job.Package.Name != "wazuh-agent.deb" {
		t.Fatalf("unexpected package view: %+v", created.Job.Package)
	}
	if len(created.Job.Package.EnvKeys) != 1 || created.Job.Package.EnvKeys[0] != "WAZUH_MANAGER" {
		t.Fatalf("unexpected env keys: %+v", created.Job.Package.EnvKeys)
	}
	if strings.Contains(string(raw), "10.0.0.5") || strings.Contains(string(raw), "hibp-jobs") {
		t.Fatalf("package path or environment value leaked in response: %s", raw)
	}
}

func TestPackageManagerCompatibility(t *testing.T) {
	cases := []struct {
		manager  string
		filename string
		ok       bool
	}{
		{"apt", "agent.deb", true},
		{"apt", "agent.rpm", false},
		{"dnf", "agent.rpm", true},
		{"zypper", "agent.rpm", true},
		{"pacman", "agent.pkg.tar.zst", true},
		{"apk", "agent.apk", true},
		{"", "agent.deb", true},
	}
	for _, tc := range cases {
		host := store.Host{Facts: &store.Facts{PackageManager: tc.manager}}
		err := packageManagerCompatible(host, tc.filename)
		if tc.ok && err != nil {
			t.Fatalf("%s/%s: unexpected error: %v", tc.manager, tc.filename, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%s/%s: expected incompatibility", tc.manager, tc.filename)
		}
	}
}

func TestJobAPIRebootRequiresConfirmation(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHostKey(store.HostKey{
		HostID: host.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:test",
	}); err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"reboot","host_ids":["`+host.ID+`"]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected reboot confirmation rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestHelperSetupJobKeepsSharedSudoPasswordOutOfStorage(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"helper-setup","host_ids":["`+host.ID+`"],"confirm":"setup","sudo_password":"super-secret"}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected created helper-setup job, got %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Job jobView `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := app.jobSudoPassword(created.Job.ID); got != "super-secret" {
		t.Fatalf("expected in-memory sudo password, got %q", got)
	}
	stored, err := db.GetJob(created.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.Payload, "super-secret") {
		t.Fatalf("sudo password leaked into persisted job payload: %s", stored.Payload)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/jobs/"+created.Job.ID, "test-token", "")
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("sudo password leaked into job API response: %s", raw)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs/"+created.Job.ID+"/cancel", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected queued job cancel, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if got := app.jobSudoPassword(created.Job.ID); got != "" {
		t.Fatalf("expected sudo password to be cleared after cancel, got %q", got)
	}
}

func TestJobRejectsSudoPasswordForNonHelperSetup(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"facts","host_ids":["`+host.ID+`"],"sudo_password":"super-secret"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected sudo password rejection for facts job, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestRunbookJobAcceptsTypedActionsAndSudoPassword(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"runbook","host_ids":["`+host.ID+`"],"confirm":"run","sudo_password":"super-secret","runbook":{"action":"service-restart","unit":"nginx.service"}}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected created runbook job, got %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Job jobView `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Job.Kind != "runbook" || created.Job.Status != store.JobQueued {
		t.Fatalf("unexpected runbook job: %+v", created.Job)
	}
	if got := app.jobSudoPassword(created.Job.ID); got != "super-secret" {
		t.Fatalf("expected in-memory sudo password, got %q", got)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs/"+created.Job.ID+"/cancel", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected queued cancel, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if got := app.jobSudoPassword(created.Job.ID); got != "" {
		t.Fatalf("expected sudo password clear, got %q", got)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"runbook","host_ids":["`+host.ID+`"],"confirm":"remove","runbook":{"action":"package-remove-apply","packages":["bad;rm -rf /"]}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid package rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"runbook","host_ids":["`+host.ID+`"],"confirm":"register","runbook":{"action":"checkmk-register","checkmk":{"server":"checkmk:8000","site":"Bergling","user":"cmkadmin","password":"checkmk-secret"}}}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected created Checkmk runbook job, got %d %s", resp.StatusCode, raw)
	}
	var checkmkCreated struct {
		Job jobView `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&checkmkCreated); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := app.jobCheckmkPassword(checkmkCreated.Job.ID); got != "checkmk-secret" {
		t.Fatalf("expected in-memory Checkmk password, got %q", got)
	}
	stored, err := db.GetJob(checkmkCreated.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.Payload, "checkmk-secret") {
		t.Fatalf("Checkmk password leaked into the persisted job payload: %s", stored.Payload)
	}
	if !strings.Contains(stored.Payload, `"server":"checkmk:8000"`) || !strings.Contains(stored.Payload, `"site":"Bergling"`) {
		t.Fatalf("Checkmk settings missing from the persisted job payload: %s", stored.Payload)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs/"+checkmkCreated.Job.ID+"/cancel", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected queued Checkmk cancel, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if got := app.jobCheckmkPassword(checkmkCreated.Job.ID); got != "" {
		t.Fatalf("expected Checkmk password clear, got %q", got)
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/jobs", "test-token",
		`{"kind":"runbook","host_ids":["`+host.ID+`"],"confirm":"register","runbook":{"action":"checkmk-register","checkmk":{"server":"bad server","site":"Bergling","user":"cmkadmin","password":"checkmk-secret"}}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected invalid Checkmk server rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
