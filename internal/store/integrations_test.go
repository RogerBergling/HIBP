package store

import "testing"

func TestIntegrationStateAndEvents(t *testing.T) {
	s := openAuthTestStore(t)
	if err := s.UpsertIntegrationState(IntegrationState{
		Source: "haproxy", EventKey: "web/app01", Status: "critical",
		Subject: "HAProxy server down", Detail: "status DOWN", FirstSeen: "2026-11-11T10:00:00Z",
		LastSeen: "2026-11-11T10:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetIntegrationState("haproxy", "web/app01")
	if err != nil || state.Status != "critical" {
		t.Fatalf("state: %+v %v", state, err)
	}
	states, err := s.ListIntegrationStates("haproxy")
	if err != nil || len(states) != 1 {
		t.Fatalf("states: %+v %v", states, err)
	}
	if err := s.UpsertIntegrationState(IntegrationState{
		Source: "haproxy", EventKey: "web/app01", Status: "warning",
		Subject: "HAProxy server warning", Detail: "status NOLB", FirstSeen: "2026-11-11T10:00:00Z",
		LastSeen: "2026-11-11T10:05:00Z", LastNotified: "2026-11-11T10:05:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	state, _ = s.GetIntegrationState("haproxy", "web/app01")
	if state.Status != "warning" || state.LastNotified == "" {
		t.Fatalf("updated state: %+v", state)
	}
	if err := s.AddIntegrationEvent(IntegrationEvent{
		Source: "haproxy", EventKey: "web/app01", Status: "critical",
		Subject: "HAProxy server down", Detail: "status DOWN", CreatedAt: "2026-11-11T10:00:00Z", Emailed: true,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListIntegrationEvents(10)
	if err != nil || len(events) != 1 || !events[0].Emailed {
		t.Fatalf("events: %+v %v", events, err)
	}
	if err := s.DeleteIntegrationState("haproxy", "web/app01"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIntegrationState("haproxy", "web/app01"); err == nil {
		t.Fatal("state still exists after delete")
	}
}
