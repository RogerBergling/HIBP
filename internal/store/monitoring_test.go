package store

import (
	"database/sql"
	"errors"
	"testing"
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
	if err := s.DeleteMonitor(monitor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetMonitor(monitor.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected monitor deletion, got %v", err)
	}
}
