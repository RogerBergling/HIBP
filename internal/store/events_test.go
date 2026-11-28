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

func TestHostEventsSuppressedFiltering(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "udm", Address: "192.168.4.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.AddHostEvents(host.ID, []HostEvent{
		{EventID: "visible-1", Source: "syslog", Category: "network_wifi", Severity: "info", Message: "visible", OccurredAt: now},
		{EventID: "visible-2", Source: "syslog", Category: "syslog", Severity: "info", Message: "visible syslog", OccurredAt: now},
		{EventID: "suppressed-1", Source: "syslog", Category: "syslog", Severity: "info", Message: "hidden noise", OccurredAt: now, Suppressed: true, PolicyID: "policy-1"},
		{EventID: "guarded-1", Source: "syslog", Category: "system", Severity: "critical", Message: "kernel: I/O error", OccurredAt: now, Suppressed: true, Guardrail: true, PolicyID: "policy-1"},
	}); err != nil {
		t.Fatal(err)
	}
	usage, err := s.SyslogPolicyUsage()
	if err != nil || usage["policy-1"].Suppressed != 1 || usage["policy-1"].Guardrails != 1 {
		t.Fatalf("unexpected policy usage: %+v %v", usage, err)
	}
	visible, err := s.ListHostEvents(10)
	if err != nil || len(visible) != 3 {
		t.Fatalf("visible events: %+v %v", visible, err)
	}
	for _, event := range visible {
		if event.Suppressed {
			t.Fatalf("suppressed event leaked into default list: %+v", event)
		}
	}
	all, err := s.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(all) != 4 {
		t.Fatalf("all events: %+v %v", all, err)
	}
	summary, err := s.SummarizeHostEvents("")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Total != 3 || summary.Suppressed != 1 {
		t.Fatalf("unexpected visible summary: %+v", summary)
	}
	allSummary, err := s.SummarizeHostEventsIncludingSuppressed("", true)
	if err != nil {
		t.Fatal(err)
	}
	if allSummary.Total != 4 || allSummary.Suppressed != 1 {
		t.Fatalf("unexpected full summary: %+v", allSummary)
	}
	count, err := s.CountHostEventsSince(host.ID, "syslog", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err != nil || count != 1 {
		t.Fatalf("suppressed event must not count toward monitors: %d %v", count, err)
	}
	matching, err := s.CountHostEventsMatching(host.ID, "syslog", "visible", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err != nil || matching != 2 {
		t.Fatalf("visible syslog match count: %d %v", matching, err)
	}
	hidden, err := s.CountHostEventsMatching(host.ID, "syslog", "hidden", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano))
	if err != nil || hidden != 0 {
		t.Fatalf("suppressed syslog match count: %d %v", hidden, err)
	}
}

func TestSyslogPolicyCRUD(t *testing.T) {
	s := openAuthTestStore(t)
	policy, err := s.CreateSyslogPolicy(SyslogPolicy{
		Name: "Noise", Scope: "fleet", MatchType: "contains", Pattern: "mc2uc",
		Category: "network_wifi", Severity: "info", Suppress: true,
		Priority: 10, Enabled: true, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.ID == "" {
		t.Fatal("expected generated policy id")
	}
	loaded, err := s.GetSyslogPolicy(policy.ID)
	if err != nil || loaded.Name != "Noise" || !loaded.Suppress || !loaded.Enabled {
		t.Fatalf("unexpected policy: %+v %v", loaded, err)
	}
	loaded.Severity = "warning"
	loaded.Suppress = false
	if err := s.UpdateSyslogPolicy(loaded); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetSyslogPolicy(policy.ID)
	if err != nil || updated.Severity != "warning" || updated.Suppress {
		t.Fatalf("unexpected updated policy: %+v %v", updated, err)
	}
	list, err := s.ListSyslogPolicies()
	if err != nil || len(list) != 1 {
		t.Fatalf("policies: %+v %v", list, err)
	}
	if err := s.DeleteSyslogPolicy(policy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSyslogPolicy(policy.ID); err == nil {
		t.Fatal("expected deleted policy to be gone")
	}
}

func TestHostEventAcknowledgement(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "jump", Address: "10.0.0.70", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.AddHostEvents(host.ID, []HostEvent{
		{
			EventID: "ack-1", Source: "session.scope", Category: "auth_failure",
			Severity: "critical", Message: "pam_unix authentication failure", OccurredAt: now,
		},
		{
			EventID: "ack-2", Source: "syslog", Category: "syslog",
			Severity: "warning", Message: "service restart", OccurredAt: now,
		},
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListHostEvents(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v %v", events, err)
	}
	ids := map[string]int64{}
	for _, event := range events {
		ids[event.EventID] = event.ID
	}
	found, err := s.AcknowledgeHostEvent(ids["ack-1"], "roger", "reviewed", now)
	if err != nil || !found {
		t.Fatalf("acknowledge: found=%v err=%v", found, err)
	}
	events, err = s.ListHostEvents(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events after ack: %+v %v", events, err)
	}
	var acknowledged HostEvent
	for _, event := range events {
		if event.EventID == "ack-1" {
			acknowledged = event
		}
	}
	if acknowledged.AcknowledgedAt == "" || acknowledged.AcknowledgedBy != "roger" ||
		acknowledged.AcknowledgementNote != "reviewed" || acknowledged.Severity != "critical" {
		t.Fatalf("unexpected acknowledged event: %+v", acknowledged)
	}
	summary, err := s.SummarizeHostEvents("")
	if err != nil || summary.Acknowledged != 1 || summary.AcknowledgedCritical != 1 ||
		summary.AcknowledgedWarning != 0 {
		t.Fatalf("unexpected summary: %+v %v", summary, err)
	}
	if _, err := s.AcknowledgeHostEvent(ids["ack-2"], "roger", "", now); err != nil {
		t.Fatal(err)
	}
	summary, err = s.SummarizeHostEvents("")
	if err != nil || summary.Acknowledged != 2 || summary.AcknowledgedCritical != 1 ||
		summary.AcknowledgedWarning != 1 {
		t.Fatalf("unexpected per-severity summary: %+v %v", summary, err)
	}
	found, err = s.UnacknowledgeHostEvent(ids["ack-1"])
	if err != nil || !found {
		t.Fatalf("unacknowledge: found=%v err=%v", found, err)
	}
	summary, err = s.SummarizeHostEvents("")
	if err != nil || summary.Acknowledged != 1 || summary.AcknowledgedCritical != 0 ||
		summary.AcknowledgedWarning != 1 {
		t.Fatalf("unexpected summary after unack: %+v %v", summary, err)
	}
	if _, err := s.UnacknowledgeHostEvent(ids["ack-2"]); err != nil {
		t.Fatal(err)
	}
	summary, _ = s.SummarizeHostEvents("")
	if summary.Acknowledged != 0 || summary.AcknowledgedWarning != 0 {
		t.Fatalf("summary still shows acknowledged: %+v", summary)
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
	if events[0].Severity != "critical" {
		t.Fatalf("auth failures must be normalized to critical: %+v", events[0])
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
