package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
)

func TestAgentTokenSnapshotAndEvents(t *testing.T) {
	ts, db, _ := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "win11", Address: "10.0.0.50", Port: 22, Username: "SYSTEM",
		AuthType: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/agent", "test-token", `{}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("create agent token: %d %s", resp.StatusCode, raw)
	}
	var created agentCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Token == "" {
		t.Fatal("expected a one-time agent token")
	}

	postAgent := func(path string, payload any, token string) *http.Response {
		body, _ := json.Marshal(payload)
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp = postAgent("/api/v1/agent/v1/heartbeat", agentHeartbeat{Platform: "windows", Version: "test"}, created.Token)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("heartbeat: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()

	facts := helper.Facts{
		OSPrettyName: "Windows 11 Pro", Kernel: "10.0.26100",
		TimeSyncOK: true, TimeSyncSource: "w32time", TimeSyncOffsetKnown: false,
	}
	snapshot := agentSnapshot{
		Facts: &facts,
		Services: &agentServices{
			Running: []string{"Spooler", "W32Time"},
			Failed:  []string{},
		},
	}
	resp = postAgent("/api/v1/agent/v1/snapshot", snapshot, created.Token)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("snapshot: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	updated, err := db.GetHost(host.ID)
	if err != nil || updated.Facts == nil || updated.Facts.OSPrettyName != "Windows 11 Pro" {
		t.Fatalf("agent facts not stored: %+v %v", updated.Facts, err)
	}
	baseline, err := db.ListServiceBaseline(host.ID)
	if err != nil || len(baseline) != 2 {
		t.Fatalf("agent service baseline: %+v %v", baseline, err)
	}

	events := []helper.Event{{
		EventID: "win-security-4625-1", Source: "Security/4625", Category: "auth_failure",
		Severity: "warning", Message: "An account failed to log on",
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}}
	resp = postAgent("/api/v1/agent/v1/events", agentEvents{Events: events}, created.Token)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("events: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	stored, err := db.ListHostEvents(10)
	if err != nil || len(stored) != 1 || stored[0].Category != "auth_failure" {
		t.Fatalf("agent events not stored: %+v %v", stored, err)
	}
	if stored[0].Severity != "critical" {
		t.Fatalf("agent auth failure must be critical: %+v", stored[0])
	}

	resp = postAgent("/api/v1/agent/v1/heartbeat", agentHeartbeat{Platform: "windows", Version: "test"}, "wrong-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected bad token rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/hosts/"+host.ID+"/agent", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("revoke agent: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	resp = postAgent("/api/v1/agent/v1/heartbeat", agentHeartbeat{Platform: "windows", Version: "test"}, created.Token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked token rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if !strings.Contains(created.Agent.HostName, "win11") {
		t.Fatalf("unexpected agent view: %+v", created.Agent)
	}
}
