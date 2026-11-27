package store

import (
	"testing"
	"time"
)

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
