package store

import (
	"testing"
	"time"
)

func TestSummarizeHostEvents(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "udm", Address: "192.168.4.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	recent := now.Add(-time.Hour).Format(time.RFC3339Nano)
	old := now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if err := s.AddHostEvents(host.ID, []HostEvent{
		{EventID: "summary-1", Source: "syslog", Category: "network_wan", Severity: "critical", Message: "WAN down", OccurredAt: recent},
		{EventID: "summary-2", Source: "syslog", Category: "network_wan", Severity: "warning", Message: "WAN up", OccurredAt: recent},
		{EventID: "summary-3", Source: "syslog", Category: "syslog", Severity: "info", Message: "informational", OccurredAt: recent},
		{EventID: "summary-4", Source: "syslog", Category: "auth_failure", Severity: "critical", Message: "login failed", OccurredAt: old},
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := s.SummarizeHostEvents("")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 4 || summary.Critical != 2 || summary.Warning != 1 || summary.Info != 1 || summary.Other != 0 {
		t.Fatalf("unexpected totals: %+v", summary)
	}
	if summary.LastOccurredAt == "" || summary.LastCritical == "" || summary.LastWarning == "" || summary.LastInfo == "" {
		t.Fatalf("missing last timestamps: %+v", summary)
	}
	if len(summary.Hosts) != 1 || summary.Hosts[0].Name != host.ID || summary.Hosts[0].Total != 4 {
		t.Fatalf("unexpected host summary: %+v", summary.Hosts)
	}
	recentSummary, err := s.SummarizeHostEvents(now.Add(-24 * time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if recentSummary.Total != 3 || recentSummary.Critical != 1 || recentSummary.Warning != 1 || recentSummary.Info != 1 {
		t.Fatalf("unexpected 24h totals: %+v", recentSummary)
	}
	for _, category := range recentSummary.Categories {
		if category.Name == "auth_failure" {
			t.Fatalf("old category leaked into 24h summary: %+v", recentSummary.Categories)
		}
	}
}

func TestSummarizeHostEventsEmpty(t *testing.T) {
	s := openAuthTestStore(t)
	summary, err := s.SummarizeHostEvents("")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 0 || summary.Categories == nil || summary.Hosts == nil {
		t.Fatalf("unexpected empty summary: %+v", summary)
	}
}

func TestClearHostEventsAndAlertEvents(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	monitor, err := s.CreateMonitor(Monitor{
		Name: "clear-test", Type: "host.cpu", IntervalSeconds: 60, Enabled: true,
		Assignments: []MonitorAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddHostEvents(host.ID, []HostEvent{
		{EventID: "clear-1", Source: "syslog", Category: "network_wan", Severity: "critical", Message: "WAN down", OccurredAt: now},
		{EventID: "clear-2", Source: "syslog", Category: "network_link", Severity: "warning", Message: "link down", OccurredAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAlertEvent(AlertEvent{
		MonitorID: monitor.ID, HostID: host.ID, Status: "critical", Subject: "WAN down",
		Detail: "WAN down", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.ClearHostEvents(host.ID)
	if err != nil || deleted != 2 {
		t.Fatalf("clear events: deleted=%d err=%v", deleted, err)
	}
	if events, err := s.ListHostEvents(10); err != nil || len(events) != 0 {
		t.Fatalf("events after clear: %+v %v", events, err)
	}
	deleted, err = s.ClearAlertEvents()
	if err != nil || deleted != 1 {
		t.Fatalf("clear alerts: deleted=%d err=%v", deleted, err)
	}
	if alerts, err := s.ListAlertEvents(10); err != nil || len(alerts) != 0 {
		t.Fatalf("alerts after clear: %+v %v", alerts, err)
	}
}

func TestHostEventsAreDeduplicatedAndCounted(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	event := HostEvent{
		EventID: "cursor-1", Source: "ssh.service", Category: "auth_failure",
		Severity: "warning", Username: "admin", RemoteIP: "192.0.2.10",
		Message: "Failed password", OccurredAt: now,
	}
	if err := s.AddHostEvents(host.ID, []HostEvent{event, event}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListHostEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %+v %v", events, err)
	}
	count, err := s.CountHostEventsSince(host.ID, "auth_failure", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err != nil || count != 1 {
		t.Fatalf("count: %d %v", count, err)
	}
	if err := s.DeleteHostEventsBeforeForHost(host.ID, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	events, err = s.ListHostEvents(10)
	if err != nil || len(events) != 0 {
		t.Fatalf("events not deleted: %+v %v", events, err)
	}
}
