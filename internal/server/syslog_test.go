package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
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

func TestParseSyslogWithoutPriority(t *testing.T) {
	msg, err := parseSyslogMessage(`WAN down UDM event without a priority header`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Message != "WAN down UDM event without a priority header" || msg.Severity != 6 {
		t.Fatalf("unexpected fallback message: %+v", msg)
	}
	if category, severity := syslogEventClass(msg); category != "network_wan" || severity != "critical" {
		t.Fatalf("unexpected fallback classification: %s/%s", category, severity)
	}
}

func TestQNAPLoginFailIsCritical(t *testing.T) {
	const qnapLine = `qulogd: conn log: Users: asdc, Source IP: 192.168.7.10, Computer name: ---, Connection type: HTTPS, Accessed resources: Administration, Action: Login Fail`
	msg, err := parseSyslogMessage(qnapLine, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if category, severity := syslogEventClass(msg); category != "auth_failure" || severity != "critical" {
		t.Fatalf("unexpected QNAP classification: %s/%s", category, severity)
	}
	_, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "qnap", Address: "10.0.0.60", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	app.handleSyslogMessage("10.0.0.60",
		`<134>Nov 28 00:12:34 QNAP qulogd: conn log: Users: asdc, Source IP: 192.168.7.10, Computer name: ---, Connection type: HTTPS, Accessed resources: Administration, Action: Login Fail`)
	events, err := db.ListHostEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %+v %v", events, err)
	}
	event := events[0]
	if event.HostID != host.ID || event.Category != "auth_failure" || event.Severity != "critical" ||
		event.Username != "asdc" || event.RemoteIP != "192.168.7.10" {
		t.Fatalf("unexpected QNAP event: %+v", event)
	}
}

func TestParseCEFWithRFC3164Priority(t *testing.T) {
	line := `<134>Nov 27 23:57:03 UDM CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIclientAlias=Kamera-Framsida UNIFIclientMac=aa:bb:cc:dd:ee:ff UNIFIwifiName=TV msg=Kamera-Framsida disconnected from TV. Time Connected: 2d 11h.`
	msg, err := parseSyslogMessage(line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.CEF == nil {
		t.Fatalf("expected CEF fields: %+v", msg)
	}
	if msg.CEF.Name != "WiFi Client Disconnected" || msg.CEF.Severity != 2 {
		t.Fatalf("unexpected CEF header: %+v", msg.CEF)
	}
	if msg.CEF.Extensions["unificlientalias"] != "Kamera-Framsida" ||
		msg.CEF.Extensions["unifiwifiname"] != "TV" {
		t.Fatalf("unexpected CEF extensions: %+v", msg.CEF.Extensions)
	}
	if !strings.HasPrefix(msg.Message, "CEF:0|Ubiquiti|") {
		t.Fatalf("expected complete CEF payload, got %q", msg.Message)
	}
	if category, severity := syslogEventClass(msg); category != "network_wifi" || severity != "info" {
		t.Fatalf("unexpected CEF classification: %s/%s", category, severity)
	}
}

func TestParseCEFMessage(t *testing.T) {
	line := `Nov 27 23:13:54 UDM CEF:0|Ubiquiti|UniFi Network|6.0.19|EVT_GW_WANTransition|WAN Transition|8|cat=network dvc=192.168.4.1 suser=admin src=192.168.4.50 msg=WAN 1 transitioned to down`
	msg, err := parseSyslogMessage(line, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if msg.CEF == nil {
		t.Fatalf("expected CEF fields: %+v", msg)
	}
	if msg.CEF.Vendor != "Ubiquiti" || msg.CEF.Product != "UniFi Network" ||
		msg.CEF.EventID != "EVT_GW_WANTransition" || msg.CEF.Name != "WAN Transition" ||
		msg.CEF.Severity != 8 {
		t.Fatalf("unexpected CEF header: %+v", msg.CEF)
	}
	if msg.CEF.Extensions["suser"] != "admin" || msg.CEF.Extensions["src"] != "192.168.4.50" ||
		msg.CEF.Extensions["msg"] != "WAN 1 transitioned to down" {
		t.Fatalf("unexpected CEF extensions: %+v", msg.CEF.Extensions)
	}
	if category, severity := syslogEventClass(msg); category != "network_wan" || severity != "critical" {
		t.Fatalf("unexpected CEF classification: %s/%s", category, severity)
	}
}

func TestCEFAuthClassification(t *testing.T) {
	msg, err := parseSyslogMessage(`CEF:0|Ubiquiti|UniFi Network|6.0.19|EVT_ADMIN_LOGIN_FAILED|Admin login failed|5|suser=admin src=192.168.4.50`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	category, severity := syslogEventClass(msg)
	if category != "auth_failure" || severity != "critical" {
		t.Fatalf("unexpected CEF auth classification: %s/%s", category, severity)
	}
}

func TestHandleSyslogMessageKeepsLongCEF(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "udm", Address: "10.0.0.50", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", 900)
	app.handleSyslogMessage("10.0.0.50",
		`CEF:0|Ubiquiti|UniFi Network|6.0.19|EVT_TEST|Test event|3|suser=admin msg=`+padding)
	events, err := db.ListHostEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %+v %v", events, err)
	}
	if events[0].HostID != host.ID || events[0].Username != "admin" {
		t.Fatalf("unexpected stored event: %+v", events[0])
	}
	if len(events[0].Message) <= 512 || !strings.Contains(events[0].Message, padding) {
		t.Fatalf("expected a full long CEF message, got %d bytes", len(events[0].Message))
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
		{"authentication failure for user admin", "auth_failure", "critical"},
		{"Login Fail for user admin", "auth_failure", "critical"},
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

func TestSNMPPollEndpoint(t *testing.T) {
	ts, db := testServer(t)
	networkHost, err := db.CreateHost(store.Host{
		Name: "udm", Address: "192.0.2.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	sshHost, err := db.CreateHost(store.Host{
		Name: "web", Address: "192.0.2.2", Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+networkHost.ID+"/snmp/poll", "test-token", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		_ = resp.Body.Close()
		t.Fatalf("expected disabled SNMP poll rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if err := db.SetSetting("host:"+networkHost.ID, "snmp.enabled", "1"); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+networkHost.ID+"/snmp/poll", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("expected SNMP poll response, got %d", resp.StatusCode)
	}
	var result struct {
		State  store.SNMPPollState `json:"state"`
		Values []store.SNMPValue   `json:"values"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(result.State.LastError, "community") || len(result.Values) != 0 {
		t.Fatalf("unexpected SNMP poll result: %+v", result)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+sshHost.ID+"/snmp/poll", "test-token", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		_ = resp.Body.Close()
		t.Fatalf("expected non-network SNMP poll rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestSNMPPDUValue(t *testing.T) {
	if value, kind := snmpPDUValue(gosnmp.SnmpPDU{Value: uint32(42)}); value != "42" || kind != "number" {
		t.Fatalf("unexpected numeric conversion: %s %s", value, kind)
	}
	if value, kind := snmpPDUValue(gosnmp.SnmpPDU{Value: []byte("udm")}); value != "udm" || kind != "string" {
		t.Fatalf("unexpected string conversion: %s %s", value, kind)
	}
}

func TestSNMPPollErrorHintsTimeout(t *testing.T) {
	message := snmpPollError("192.168.4.1", 161, "2c", errors.New("request timeout (after 1 retries)"))
	if !strings.Contains(message, "192.168.4.1:161") || !strings.Contains(message, "SNMP v2c") ||
		!strings.Contains(message, "verify the host address") {
		t.Fatalf("missing timeout diagnostics: %q", message)
	}
}
