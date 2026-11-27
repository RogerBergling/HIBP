package store

import (
	"testing"
)

func TestNetworkHostAndSNMPValues(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "udm", Address: "192.168.6.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.Port != 161 || host.AuthType != "network" || host.Username != "" {
		t.Fatalf("unexpected network host: %+v", host)
	}
	values := []SNMPValue{
		{HostID: host.ID, OID: "1.3.6.1.2.1.1.3.0", Value: "12345", ValueType: "number", CollectedAt: "2026-11-27T14:00:00Z"},
		{HostID: host.ID, OID: "1.3.6.1.2.1.1.5.0", Value: "udm", ValueType: "string", CollectedAt: "2026-11-27T14:00:00Z"},
	}
	if err := s.SaveSNMPValues(host.ID, "2026-11-27T14:00:00Z", values); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.ListSNMPValues(host.ID)
	if err != nil || len(loaded) != 2 {
		t.Fatalf("values: %+v %v", loaded, err)
	}
	value, err := s.GetSNMPValue(host.ID, "1.3.6.1.2.1.1.3.0")
	if err != nil || value.Value != "12345" || value.ValueType != "number" {
		t.Fatalf("value: %+v %v", value, err)
	}
	if err := s.SetSNMPPollState(host.ID, "2026-11-27T14:00:00Z", ""); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetSNMPPollState(host.ID)
	if err != nil || state.LastPoll != "2026-11-27T14:00:00Z" || state.LastError != "" {
		t.Fatalf("poll state: %+v %v", state, err)
	}
	if err := s.SetSNMPPollState(host.ID, "2026-11-27T14:01:00Z", "timeout"); err != nil {
		t.Fatal(err)
	}
	state, err = s.GetSNMPPollState(host.ID)
	if err != nil || state.LastError != "timeout" {
		t.Fatalf("poll error state: %+v %v", state, err)
	}
	if err := s.DeleteHost(host.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSNMPValue(host.ID, "1.3.6.1.2.1.1.3.0"); err == nil {
		t.Fatal("expected SNMP values to be deleted with the host")
	}
	if _, err := s.GetSNMPPollState(host.ID); err == nil {
		t.Fatal("expected SNMP poll state to be deleted with the host")
	}
}

func TestNetworkHostRequiresAddress(t *testing.T) {
	s := openAuthTestStore(t)
	if _, err := s.CreateHost(Host{Name: "udm", Address: "", AuthType: "network"}); err == nil {
		t.Fatal("expected network host without address to be rejected")
	}
	if _, err := s.CreateHost(Host{Name: "web", Address: "10.0.0.10", AuthType: "key", KeyPath: "/tmp/key"}); err == nil {
		t.Fatal("expected key host without username to be rejected")
	}
}
