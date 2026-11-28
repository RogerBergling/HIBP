package helper

import "testing"

func TestParseJournalAuthEvent(t *testing.T) {
	line := `{"__CURSOR":"cursor-1","__REALTIME_TIMESTAMP":"1764220800000000","_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid user admin from 192.0.2.10 port 2222 ssh2"}`
	event, ok := parseJournalEvent(line)
	if !ok {
		t.Fatal("expected auth event")
	}
	if event.EventID != "cursor-1" || event.Category != "auth_failure" || event.Severity != "critical" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.Username != "admin" || event.RemoteIP != "192.0.2.10" {
		t.Fatalf("identity not extracted: %+v", event)
	}
	if event.OccurredAt == "" {
		t.Fatal("expected timestamp")
	}
}

func TestParseJournalServiceAndOOMEvents(t *testing.T) {
	serviceLine := `{"__CURSOR":"cursor-service","__REALTIME_TIMESTAMP":"1764220800000000","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"nginx.service: Failed with result 'exit-code'."}`
	event, ok := parseJournalEvent(serviceLine)
	if !ok || event.Category != "service_failure" || event.Severity != "critical" {
		t.Fatalf("unexpected service event: %+v", event)
	}

	oomLine := `{"__CURSOR":"cursor-oom","__REALTIME_TIMESTAMP":"1764220800000000","_TRANSPORT":"kernel","MESSAGE":"Out of memory: Killed process 1234 (node)"}`
	event, ok = parseJournalEvent(oomLine)
	if !ok || event.Category != "oom" || event.Severity != "critical" {
		t.Fatalf("unexpected OOM event: %+v", event)
	}
}

func TestParseJournalIgnoresNoise(t *testing.T) {
	line := `{"__CURSOR":"cursor-noise","__REALTIME_TIMESTAMP":"1764220800000000","_SYSTEMD_UNIT":"cron.service","MESSAGE":"pam_unix(cron:session): session opened"}`
	if _, ok := parseJournalEvent(line); ok {
		t.Fatal("expected informational log to be ignored")
	}
}
