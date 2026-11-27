package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestMonitorAndServiceLifecycle(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", GroupName: "web", Tags: "prod,web",
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := s.CreateMonitor(Monitor{
		Name: "CPU high", Type: "host.cpu", Warning: 80, Critical: 90,
		IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		Assignments: []MonitorAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if monitor.ID == "" {
		t.Fatal("expected monitor id")
	}
	assignments, err := s.ListMonitorAssignments(monitor.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Scope != "fleet" {
		t.Fatalf("assignments: %+v %v", assignments, err)
	}
	monitor.Name = "CPU very high"
	monitor.Assignments = []MonitorAssignment{{Scope: "host", Target: host.ID}, {Scope: "group", Target: "web"}}
	if err := s.UpdateMonitor(monitor); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetMonitor(monitor.ID)
	if err != nil || loaded.Name != "CPU very high" {
		t.Fatalf("loaded monitor: %+v %v", loaded, err)
	}
	assignments, _ = s.ListMonitorAssignments(monitor.ID)
	if len(assignments) != 2 {
		t.Fatalf("expected two assignments, got %+v", assignments)
	}

	if err := s.UpsertMonitorState(MonitorState{
		MonitorID: monitor.ID, HostID: host.ID, Status: "critical", Message: "92%",
		CheckedAt: "2026-11-11T08:00:00Z", ChangedAt: "2026-11-11T08:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetMonitorState(monitor.ID, host.ID)
	if err != nil || state.Status != "critical" {
		t.Fatalf("state: %+v %v", state, err)
	}
	states, err := s.ListMonitorStates(monitor.ID)
	if err != nil || len(states) != 1 {
		t.Fatalf("states: %+v %v", states, err)
	}
	if err := s.AddAlertEvent(AlertEvent{
		MonitorID: monitor.ID, HostID: host.ID, Status: "critical", Subject: "CPU high",
		Detail: "92%", CreatedAt: "2026-11-11T08:00:00Z", Emailed: true,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListAlertEvents(10)
	if err != nil || len(events) != 1 || !events[0].Emailed {
		t.Fatalf("events: %+v %v", events, err)
	}

	if err := s.SaveServiceState(host.ID, []string{"nginx.service"}, []string{"ssh.service", "docker.service"}); err != nil {
		t.Fatal(err)
	}
	service, err := s.GetServiceState(host.ID, "ssh.service")
	if err != nil || service.State != "running" {
		t.Fatalf("service: %+v %v", service, err)
	}
	services, err := s.ListServiceStates(host.ID)
	if err != nil || len(services) != 3 {
		t.Fatalf("services: %+v %v", services, err)
	}
	if err := s.DeleteHost(host.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMonitorState(monitor.ID, host.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected deleted host monitor state to be removed, got %v", err)
	}
	if err := s.DeleteMonitor(monitor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMonitor(monitor.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected monitor deletion, got %v", err)
	}
}

func TestSyncServiceBaselineAddsNewRunningUnits(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncServiceBaseline(host.ID, []string{"ssh.service", "cron.service"}, true); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncServiceBaseline(host.ID, []string{"ssh.service", "nginx.service"}, true); err != nil {
		t.Fatal(err)
	}
	baseline, err := s.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	units := map[string]ServiceBaseline{}
	for _, item := range baseline {
		units[item.Unit] = item
	}
	for _, want := range []string{"ssh.service", "cron.service", "nginx.service"} {
		if _, ok := units[want]; !ok {
			t.Fatalf("expected %s in expanded baseline, got %+v", want, baseline)
		}
	}
}

func TestServiceBaselineExclusionsAndReset(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureServiceBaseline(host.ID, []string{"ssh.service", "cron.service", "packagekit.service"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceBaselineExcluded(host.ID, "packagekit.service", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceBaselineExcluded(host.ID, "failed-only.service", true); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetServiceBaseline(host.ID, []string{"ssh.service", "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	baseline, err := s.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	units := map[string]ServiceBaseline{}
	for _, item := range baseline {
		units[item.Unit] = item
	}
	if _, ok := units["cron.service"]; ok {
		t.Fatalf("non-excluded unit that disappeared survived reset: %+v", baseline)
	}
	for _, want := range []string{"ssh.service", "nginx.service"} {
		item, ok := units[want]
		if !ok || !item.Expected || item.Excluded {
			t.Fatalf("expected running unit %s to be reset as expected: %+v", want, item)
		}
	}
	for _, want := range []string{"packagekit.service", "failed-only.service"} {
		item, ok := units[want]
		if !ok || !item.Excluded {
			t.Fatalf("expected exclusion for %s to survive reset: %+v", want, item)
		}
	}
	if err := s.SetServiceBaselineExcluded(host.ID, "packagekit.service", false); err != nil {
		t.Fatal(err)
	}
	baseline, err = s.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range baseline {
		if item.Unit == "packagekit.service" && item.Excluded {
			t.Fatalf("expected packagekit.service to be included again: %+v", item)
		}
	}
	if err := s.SetServiceBaselineExcluded(host.ID, "not-tracked.service", false); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected missing baseline unit include to return ErrNoRows, got %v", err)
	}
}

func TestServiceBaselineDefaultTransientExclusions(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureServiceBaseline(host.ID, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	// Simulate a baseline created before the default exclusion list existed.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, unit := range []string{"packagekit.service", "systemd-timedated.service"} {
		if _, err := s.db.Exec(`INSERT INTO host_service_baseline
			(host_id,unit,state,expected,excluded,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
			host.ID, unit, "running", 1, 0, now, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteSetting("host:"+host.ID, baselineDefaultExclusionsKey); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncServiceBaseline(host.ID, []string{"ssh.service"}, false); err != nil {
		t.Fatal(err)
	}
	baseline, err := s.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	excluded := map[string]bool{}
	for _, item := range baseline {
		excluded[item.Unit] = item.Excluded
	}
	if excluded["ssh.service"] {
		t.Fatal("ssh.service should not be excluded by default")
	}
	for _, unit := range []string{"packagekit.service", "systemd-timedated.service"} {
		if !excluded[unit] {
			t.Fatalf("expected %s to be excluded by default", unit)
		}
	}
	// An explicit include must survive later automatic baseline syncs.
	if err := s.SetServiceBaselineExcluded(host.ID, "systemd-timedated.service", false); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncServiceBaseline(host.ID, []string{"ssh.service"}, true); err != nil {
		t.Fatal(err)
	}
	baseline, err = s.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range baseline {
		if item.Unit == "systemd-timedated.service" && item.Excluded {
			t.Fatal("explicitly included unit was re-excluded by the default list")
		}
	}
}

func TestServiceBaselineAndDefaultMonitors(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureServiceBaseline(host.ID, []string{"ssh.service", "cron.service"}); err != nil {
		t.Fatal(err)
	}
	baseline, err := s.ListServiceBaseline(host.ID)
	if err != nil || len(baseline) != 2 {
		t.Fatalf("baseline: %+v %v", baseline, err)
	}
	if err := s.EnsureServiceBaseline(host.ID, []string{"ssh.service", "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	baseline, err = s.ListServiceBaseline(host.ID)
	if err != nil || len(baseline) != 2 {
		t.Fatalf("baseline changed after second snapshot: %+v %v", baseline, err)
	}
	for _, item := range baseline {
		if item.Unit == "nginx.service" {
			t.Fatal("new unit was added to an existing baseline")
		}
	}
	if err := s.DeleteHost(host.ID); err != nil {
		t.Fatal(err)
	}
	baseline, err = s.ListServiceBaseline(host.ID)
	if err != nil || len(baseline) != 0 {
		t.Fatalf("baseline was not removed with host: %+v %v", baseline, err)
	}

	monitors, err := s.ListMonitors()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, monitor := range monitors {
		switch monitor.ID {
		case "default-service-baseline", "default-docker-health":
			found[monitor.ID] = true
		}
	}
	if !found["default-service-baseline"] || !found["default-docker-health"] {
		t.Fatalf("expected default enterprise monitors, got %+v", monitors)
	}
}
