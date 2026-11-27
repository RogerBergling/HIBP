package server

import (
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
	"github.com/gosnmp/gosnmp"
)

func TestParseSyslogRFC5424(t *testing.T) {
	msg, err := parseSyslogMessage(`<134>1 2026-11-27T14:00:00Z udm kernel 123 ID47 - WAN down`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Facility != 16 || msg.Severity != 6 {
		t.Fatalf("unexpected priority: %+v", msg)
	}
	if msg.Hostname != "udm" || msg.AppName != "kernel" || msg.ProcID != "123" || msg.Message != "WAN down" {
		t.Fatalf("unexpected message: %+v", msg)
	}
	if msg.Timestamp.UTC().Format(time.RFC3339) != "2026-11-27T14:00:00Z" {
		t.Fatalf("unexpected timestamp: %s", msg.Timestamp)
	}
}

func TestParseSyslogRFC3164(t *testing.T) {
	msg, err := parseSyslogMessage(`<34>Nov 27 14:00:00 udm kernel: link down`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Facility != 4 || msg.Severity != 2 {
		t.Fatalf("unexpected priority: %+v", msg)
	}
	if msg.Hostname != "udm" || msg.AppName != "kernel" || msg.Message != "link down" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestSyslogEventClass(t *testing.T) {
	tests := []struct {
		message  string
		category string
		severity string
	}{
		{"WAN down", "network_wan", "critical"},
		{"WAN up", "network_wan", "warning"},
		{"link down on port 3", "network_link", "warning"},
		{"authentication failure for user admin", "auth_failure", "warning"},
		{"firmware upgrade completed", "system", "info"},
		{"random device message", "syslog", "info"},
	}
	for _, test := range tests {
		msg := syslogMessage{Severity: 6, Message: test.message}
		category, severity := syslogEventClass(msg)
		if category != test.category || severity != test.severity {
			t.Fatalf("%q: got %s/%s, want %s/%s", test.message, category, severity, test.category, test.severity)
		}
	}
}

func TestHandleSyslogMessageStoresEvent(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "udm", Address: "10.0.0.50", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	app.handleSyslogMessage("10.0.0.50", `<134>1 2026-11-27T14:00:00Z udm kernel - - - WAN down`)
	events, err := db.ListHostEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %+v %v", events, err)
	}
	if events[0].HostID != host.ID || events[0].Category != "network_wan" ||
		events[0].Severity != "critical" || events[0].RemoteIP != "10.0.0.50" {
		t.Fatalf("unexpected stored event: %+v", events[0])
	}
	if _, err := time.Parse(time.RFC3339Nano, events[0].OccurredAt); err != nil {
		t.Fatalf("invalid occurred_at: %v", err)
	}
}

func TestSyslogEventMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, event := range []store.HostEvent{
		{EventID: "syslog-1", Source: "syslog", Category: "network_wan", Severity: "critical", Message: "WAN down", OccurredAt: now},
		{EventID: "syslog-2", Source: "syslog", Category: "network_link", Severity: "warning", Message: "link down", OccurredAt: now},
	} {
		if err := db.AddHostEvents(host.ID, []store.HostEvent{event}); err != nil {
			t.Fatal(err)
		}
	}
	monitor := store.Monitor{Type: "syslog.event", Target: "wan down", Warning: 1, Critical: 2}
	result := app.evaluateSyslogEvent(monitor, host)
	if result.status != "warning" || result.message == "" {
		t.Fatalf("expected warning syslog event result, got %+v", result)
	}
	monitor.Critical = 1
	result = app.evaluateSyslogEvent(monitor, host)
	if result.status != "critical" {
		t.Fatalf("expected critical syslog event result, got %+v", result)
	}
}

func TestSNMPValueAndPollMonitors(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SetSetting("host:"+host.ID, "snmp.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("host:"+host.ID, "snmp.interval", "60s"); err != nil {
		t.Fatal(err)
	}
	collected := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.SaveSNMPValues(host.ID, collected, []store.SNMPValue{
		{HostID: host.ID, OID: "1.3.6.1.2.1.1.3.0", Value: "150", ValueType: "number", CollectedAt: collected},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSNMPPollState(host.ID, collected, ""); err != nil {
		t.Fatal(err)
	}
	monitor := store.Monitor{Type: "snmp.value", Target: ".1.3.6.1.2.1.1.3.0", Warning: 100, Critical: 200}
	result := app.evaluateSNMPValue(monitor, host)
	if result.status != "warning" {
		t.Fatalf("expected warning SNMP value, got %+v", result)
	}
	if err := db.SaveSNMPValues(host.ID, collected, []store.SNMPValue{
		{HostID: host.ID, OID: "1.3.6.1.2.1.1.3.0", Value: "250", ValueType: "number", CollectedAt: collected},
	}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateSNMPValue(monitor, host)
	if result.status != "critical" {
		t.Fatalf("expected critical SNMP value, got %+v", result)
	}
	result = app.evaluateSNMPPoll(host)
	if result.status != "ok" {
		t.Fatalf("expected successful SNMP poll, got %+v", result)
	}
	if err := db.SetSNMPPollState(host.ID, collected, "timeout"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateSNMPPoll(host)
	if result.status != "critical" || result.message == "" {
		t.Fatalf("expected failed SNMP poll, got %+v", result)
	}
	if err := db.SetSetting("host:"+host.ID, "snmp.enabled", "0"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateSNMPPoll(host)
	if result.status != "ok" || result.message == "" {
		t.Fatalf("expected disabled SNMP result, got %+v", result)
	}
}

func TestSNMPPDUValue(t *testing.T) {
	if value, kind := snmpPDUValue(gosnmp.SnmpPDU{Value: uint32(42)}); value != "42" || kind != "number" {
		t.Fatalf("unexpected numeric conversion: %s %s", value, kind)
	}
	if value, kind := snmpPDUValue(gosnmp.SnmpPDU{Value: []byte("udm")}); value != "udm" || kind != "string" {
		t.Fatalf("unexpected string conversion: %s %s", value, kind)
	}
}
