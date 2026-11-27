package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

func TestSMTPSettingsMaskPassword(t *testing.T) {
	ts, _ := testServer(t)
	base := ts.URL
	payload := `{"enabled":true,"host":"smtp.example.com","port":587,"mode":"starttls","username":"alerts","password":"super-secret-password","from":"hibp@example.com","recipients":"ops@example.com","timeout_seconds":15}`
	resp := request(t, http.MethodPut, base+"/api/v1/notifications/smtp", "test-token", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save SMTP failed: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "super-secret-password") {
		t.Fatal("SMTP password was returned by the API")
	}

	resp = request(t, http.MethodGet, base+"/api/v1/notifications/smtp", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read SMTP failed: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "super-secret-password") || strings.Contains(string(body), `"password":`) {
		t.Fatalf("SMTP password leaked in response: %s", body)
	}
	var view struct {
		SMTP struct {
			PasswordSet bool `json:"password_set"`
		} `json:"smtp"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if !view.SMTP.PasswordSet {
		t.Fatal("expected password_set after saving a password")
	}

	// A follow-up save with a blank password must retain the stored secret.
	resp = request(t, http.MethodPut, base+"/api/v1/notifications/smtp", "test-token",
		`{"enabled":true,"host":"smtp.example.com","port":587,"mode":"starttls","username":"alerts","password":"","from":"hibp@example.com","recipients":"ops@example.com","timeout_seconds":15}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("update SMTP failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()
	resp = request(t, http.MethodGet, base+"/api/v1/notifications/smtp", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"password_set":true`) {
		t.Fatalf("stored password was not retained: %s", body)
	}

	// Changing the username without supplying a new password must be rejected.
	resp = request(t, http.MethodPut, base+"/api/v1/notifications/smtp", "test-token",
		`{"enabled":true,"host":"smtp.example.com","port":587,"mode":"starttls","username":"other","password":"","from":"hibp@example.com","recipients":"ops@example.com","timeout_seconds":15}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected username-change password requirement, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodPut, base+"/api/v1/notifications/smtp", "test-token",
		`{"enabled":true,"host":"smtp.example.com","port":587,"mode":"starttls","username":"","clear_password":true,"from":"hibp@example.com","recipients":"ops@example.com","timeout_seconds":15}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("clear SMTP password failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()
	resp = request(t, http.MethodGet, base+"/api/v1/notifications/smtp", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"password_set":false`) {
		t.Fatalf("password was not cleared: %s", body)
	}
}

func startFakeSMTP(t *testing.T) (int, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				writer := bufio.NewWriter(conn)
				write := func(line string) {
					_, _ = fmt.Fprint(writer, line+"\r\n")
					_ = writer.Flush()
				}
				write("220 localhost ESMTP HIBP test")
				inData := false
				var message strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if inData {
						if line == "." {
							inData = false
							write("250 OK")
							messages <- message.String()
							message.Reset()
							continue
						}
						message.WriteString(line)
						message.WriteString("\n")
						continue
					}
					upper := strings.ToUpper(line)
					switch {
					case strings.HasPrefix(upper, "EHLO"):
						write("250-localhost")
						write("250 HELP")
					case strings.HasPrefix(upper, "DATA"):
						inData = true
						write("354 End data with <CR><LF>.<CR><LF>")
					case strings.HasPrefix(upper, "QUIT"):
						write("221 Bye")
						return
					default:
						write("250 OK")
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, messages
}

func TestSMTPTestEndpointWorksWhenDisabled(t *testing.T) {
	port, messages := startFakeSMTP(t)
	ts, _ := testServer(t)
	payload := fmt.Sprintf(`{"enabled":false,"host":"127.0.0.1","port":%d,"mode":"none","from":"hibp@example.com","recipients":"ops@example.com","timeout_seconds":5}`, port)
	resp := request(t, http.MethodPut, ts.URL+"/api/v1/notifications/smtp", "test-token", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save disabled SMTP config failed: %d %s", resp.StatusCode, body)
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/notifications/smtp/test", "test-token", `{"to":"ops@example.com"}`)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test email with disabled notifications failed: %d %s", resp.StatusCode, body)
	}
	select {
	case message := <-messages:
		if !strings.Contains(message, "Subject: HIBP SMTP test") {
			t.Fatalf("unexpected test email: %s", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("test SMTP server did not receive a message")
	}
}

func TestMonitorCRUDAndValidation(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", GroupName: "web", Tags: "prod,web",
	})
	if err != nil {
		t.Fatal(err)
	}
	base := ts.URL

	resp := request(t, http.MethodPost, base+"/api/v1/monitors", "test-token", `{"name":"Bad","type":"host.cpu","warning":80,"critical":90,"interval_seconds":60,"assignments":[]}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected assignment validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	invalidTarget := `{"name":"Bad service","type":"service.systemd","target":"nginx;rm -rf /","interval_seconds":60,"assignments":[{"scope":"fleet"}]}`
	resp = request(t, http.MethodPost, base+"/api/v1/monitors", "test-token", invalidTarget)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected target validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	wildcard := `{"name":"All containers","type":"docker.container","target":"*","interval_seconds":60,"assignments":[{"scope":"fleet"}]}`
	resp = request(t, http.MethodPost, base+"/api/v1/monitors", "test-token", wildcard)
	wildcardBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("docker.container target * should be accepted, got %d %s", resp.StatusCode, wildcardBody)
	}
	var wildcardMonitor store.Monitor
	if err := json.Unmarshal(wildcardBody, &wildcardMonitor); err != nil {
		t.Fatal(err)
	}
	resp = request(t, http.MethodDelete, base+"/api/v1/monitors/"+wildcardMonitor.ID, "test-token", "")
	resp.Body.Close()

	payload := `{"name":"Web CPU","type":"host.cpu","warning":80,"critical":90,"interval_seconds":60,"repeat_minutes":60,"cooldown_minutes":15,"enabled":true,"assignments":[{"scope":"host","target":"` + host.ID + `"},{"scope":"group","target":"web"}]}`
	resp = request(t, http.MethodPost, base+"/api/v1/monitors", "test-token", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create monitor failed: %d %s", resp.StatusCode, body)
	}
	var created store.Monitor
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("expected monitor id")
	}
	resp = request(t, http.MethodPost, base+"/api/v1/monitors/"+created.ID+"/check", "test-token", `{}`)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("check now failed: %d %s", resp.StatusCode, body)
	}

	resp = request(t, http.MethodGet, base+"/api/v1/monitors", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Web CPU") {
		t.Fatalf("list monitors failed: %d %s", resp.StatusCode, body)
	}

	update := `{"name":"Web CPU updated","type":"host.cpu","warning":70,"critical":85,"interval_seconds":120,"repeat_minutes":30,"cooldown_minutes":10,"enabled":false,"assignments":[{"scope":"tag","target":"prod"}]}`
	resp = request(t, http.MethodPut, base+"/api/v1/monitors/"+created.ID, "test-token", update)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update monitor failed: %d %s", resp.StatusCode, body)
	}
	var updated store.Monitor
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Web CPU updated" || updated.Enabled || len(updated.Assignments) != 1 || updated.Assignments[0].Scope != "tag" {
		t.Fatalf("unexpected updated monitor: %+v", updated)
	}
	resp = request(t, http.MethodPost, base+"/api/v1/monitors/"+created.ID+"/check", "test-token", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected disabled monitor check rejection, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodDelete, base+"/api/v1/monitors/"+created.ID, "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete monitor failed: %d %s", resp.StatusCode, body)
	}
	if _, err := db.GetMonitor(created.ID); err == nil {
		t.Fatal("monitor still exists after delete")
	}

	resp = request(t, http.MethodGet, base+"/api/v1/alerts?limit=10", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"alerts"`) {
		t.Fatalf("list alerts failed: %d %s", resp.StatusCode, body)
	}
}

func TestStandaloneNetworkMonitor(t *testing.T) {
	ts, _ := testServer(t)
	payload := `{"name":"App availability","type":"http","target":"https://apps.bergling.net/","interval_seconds":60,"repeat_minutes":60,"cooldown_minutes":15,"enabled":true,"assignments":[]}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create standalone HTTP monitor failed: %d %s", resp.StatusCode, body)
	}
	var created store.Monitor
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || len(created.Assignments) != 0 {
		t.Fatalf("unexpected standalone monitor: %+v", created)
	}

	update := `{"name":"App availability updated","type":"http","target":"https://apps.bergling.net/health","interval_seconds":120,"repeat_minutes":30,"cooldown_minutes":10,"enabled":true,"assignments":[]}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/monitors/"+created.ID, "test-token", update)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update standalone HTTP monitor failed: %d %s", resp.StatusCode, body)
	}
	var updated store.Monitor
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "App availability updated" || len(updated.Assignments) != 0 {
		t.Fatalf("unexpected updated standalone monitor: %+v", updated)
	}

	// Host-based checks still require at least one assignment.
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token",
		`{"name":"No assignment","type":"host.cpu","warning":80,"critical":90,"interval_seconds":60,"assignments":[]}`)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected host monitor assignment failure, got %d %s", resp.StatusCode, data)
	}
}

func TestStandaloneMonitorStateAndAlert(t *testing.T) {
	app, db, _ := newMonitorTestApp(t)
	monitor, err := db.CreateMonitor(store.Monitor{
		Name: "App availability", Type: "http", Target: "https://apps.bergling.net/",
		IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	app.recordMonitorResult(monitor, "", "", monitorResult{status: "critical", message: "HTTP 503"}, now)
	states, err := db.ListMonitorStates(monitor.ID)
	if err != nil || len(states) != 1 || states[0].HostID != "" {
		t.Fatalf("expected one standalone state with an empty host id, got %+v %v", states, err)
	}
	events, err := db.ListAlertEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected one standalone alert, got %+v %v", events, err)
	}
	if events[0].HostID != "" || !strings.Contains(events[0].Detail, "standalone probe") {
		t.Fatalf("unexpected standalone alert: %+v", events[0])
	}
	if !strings.Contains(events[0].Subject, "https://apps.bergling.net/") {
		t.Fatalf("expected the target in the alert subject, got %q", events[0].Subject)
	}
}

func TestResolveMonitorTargets(t *testing.T) {
	hosts := map[string]store.Host{
		"a": {ID: "a", Name: "web01", GroupName: "web", Tags: "prod,web"},
		"b": {ID: "b", Name: "web02", GroupName: "web", Tags: "test"},
		"c": {ID: "c", Name: "db01", GroupName: "db", Tags: "prod"},
		"n": {ID: "n", Name: "udm", AuthType: "network", Tags: "prod"},
	}
	targets, active, network := resolveMonitorTargets("host.cpu", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || network || len(targets) != 3 {
		t.Fatalf("fleet targets: %+v active=%v network=%v", targets, active, network)
	}
	targets, active, _ = resolveMonitorTargets("host.cpu", []store.MonitorAssignment{{Scope: "group", Target: "WEB"}}, hosts)
	if !active || len(targets) != 2 {
		t.Fatalf("group targets: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("host.cpu", []store.MonitorAssignment{{Scope: "tag", Target: "prod"}}, hosts)
	if !active || len(targets) != 2 {
		t.Fatalf("tag targets: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("host.cpu", []store.MonitorAssignment{{Scope: "host", Target: "c"}}, hosts)
	if !active || len(targets) != 1 || targets[0].ID != "c" {
		t.Fatalf("host targets: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("host.cpu", []store.MonitorAssignment{{Scope: "host", Target: "n"}}, hosts)
	if active || len(targets) != 0 {
		t.Fatalf("network host must not receive host.cpu: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("snmp.poll", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || len(targets) != 1 || targets[0].ID != "n" {
		t.Fatalf("snmp fleet targets: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("service.baseline", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || len(targets) != 3 {
		t.Fatalf("service baseline must exclude network hosts: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("syslog.event", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || len(targets) != 1 || targets[0].ID != "n" {
		t.Fatalf("syslog fleet targets: %+v active=%v", targets, active)
	}
	targets, active, _ = resolveMonitorTargets("security.auth", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || len(targets) != 4 {
		t.Fatalf("security auth fleet targets: %+v active=%v", targets, active)
	}
	targets, active, network = resolveMonitorTargets("http", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || !network || len(targets) != 0 {
		t.Fatalf("network targets: %+v active=%v network=%v", targets, active, network)
	}
	for _, monitorType := range []string{"http", "tcp", "ssl"} {
		targets, active, network = resolveMonitorTargets(monitorType, nil, hosts)
		if !active || !network || len(targets) != 0 {
			t.Fatalf("standalone %s: %+v active=%v network=%v", monitorType, targets, active, network)
		}
	}
	// A stale network assignment must not disable the controller-side probe.
	targets, active, network = resolveMonitorTargets("http", []store.MonitorAssignment{{Scope: "host", Target: "missing"}}, hosts)
	if !active || !network || len(targets) != 0 {
		t.Fatalf("stale network assignment: %+v active=%v network=%v", targets, active, network)
	}
}

func TestEvaluateHTTP(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okServer.Close()
	monitor := store.Monitor{Type: "http", Target: okServer.URL}
	result := evaluateHTTP(t.Context(), monitor)
	if result.status != "ok" {
		t.Fatalf("expected ok, got %+v", result)
	}

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer badServer.Close()
	result = evaluateHTTP(t.Context(), store.Monitor{Type: "http", Target: badServer.URL})
	if result.status != "critical" {
		t.Fatalf("expected critical, got %+v", result)
	}
}

func newMonitorTestApp(t *testing.T) (*Server, *store.Store, store.Host) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "inventory.hibp"), []byte("correct horse battery staple"), store.Options{
		Create: true, KDFTime: 1, KDFMemory: 64 * 1024, KDFThreads: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app, err := New(Config{Store: db, Version: "test", SSHConfigPath: filepath.Join(dir, "missing-config")})
	if err != nil {
		t.Fatal(err)
	}
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	return app, db, host
}

func TestRecordMonitorResultCooldownAndRecovery(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	monitor, err := db.CreateMonitor(store.Monitor{
		Name: "CPU", Type: "host.cpu", Warning: 80, Critical: 90,
		IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		Assignments: []store.MonitorAssignment{{Scope: "host", Target: host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Unknown data is silent and a first successful check is not a recovery.
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "unknown", message: "no metrics"}, now)
	events, err := db.ListAlertEvents(10)
	if err != nil || len(events) != 0 {
		t.Fatalf("unknown state should not alert, got %+v %v", events, err)
	}
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "ok", message: "20%"}, now.Add(30*time.Second))
	events, err = db.ListAlertEvents(10)
	if err != nil || len(events) != 0 {
		t.Fatalf("first successful check should not alert, got %+v %v", events, err)
	}

	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "critical", message: "95%"}, now.Add(time.Minute))
	events, err = db.ListAlertEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected first alert event, got %+v %v", events, err)
	}
	if events[0].Emailed || events[0].Error == "" {
		t.Fatalf("expected recorded email failure, got %+v", events[0])
	}
	state, err := db.GetMonitorState(monitor.ID, host.ID)
	if err != nil || state.Status != "critical" {
		t.Fatalf("expected critical state, got %+v %v", state, err)
	}

	// The same state inside the repeat window must not notify again.
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "critical", message: "96%"}, now.Add(2*time.Minute))
	events, _ = db.ListAlertEvents(10)
	if len(events) != 1 {
		t.Fatalf("cooldown did not suppress duplicate alert, got %d events", len(events))
	}

	// A severity transition is sent even inside the cooldown window.
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "warning", message: "85%"}, now.Add(3*time.Minute))
	events, _ = db.ListAlertEvents(10)
	if len(events) != 2 || events[0].Status != "warning" {
		t.Fatalf("expected severity transition event, got %+v", events)
	}
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "warning", message: "86%"}, now.Add(4*time.Minute))
	events, _ = db.ListAlertEvents(10)
	if len(events) != 2 {
		t.Fatalf("repeat alert should be suppressed, got %d events", len(events))
	}

	// A return to ok sends a recovery event even inside the cooldown window.
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "ok", message: "20%"}, now.Add(5*time.Minute))
	events, _ = db.ListAlertEvents(10)
	if len(events) != 3 || events[0].Status != "ok" {
		t.Fatalf("expected recovery event, got %+v", events)
	}
	state, _ = db.GetMonitorState(monitor.ID, host.ID)
	if state.Status != "ok" {
		t.Fatalf("expected ok state, got %+v", state)
	}
}

func TestDisablingMonitorClearsRecordedStates(t *testing.T) {
	ts, db, app := testServerWithApp(t, true)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := db.CreateMonitor(store.Monitor{
		Name: "CPU", Type: "host.cpu", Warning: 80, Critical: 90,
		IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		Assignments: []store.MonitorAssignment{{Scope: "host", Target: host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	app.recordMonitorResult(monitor, host.ID, host.Name, monitorResult{status: "critical", message: "95%"}, time.Now().UTC())
	if _, err := db.GetMonitorState(monitor.ID, host.ID); err != nil {
		t.Fatalf("expected a recorded monitor state: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"name": "CPU", "type": "host.cpu", "warning": 80, "critical": 90,
		"interval_seconds": 60, "repeat_minutes": 60, "cooldown_minutes": 15,
		"enabled": false, "assignments": []map[string]any{{"scope": "host", "target": host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPut, ts.URL+"/api/v1/monitors/"+monitor.ID, "test-token", string(payload))
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("disable monitor failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	if _, err := db.GetMonitorState(monitor.ID, host.ID); err == nil {
		t.Fatal("expected disabled monitor state to be cleared")
	}
}

func TestMonitorAssignmentChangeClearsOldHostStates(t *testing.T) {
	ts, db := testServer(t)
	hostA, err := db.CreateHost(store.Host{
		Name: "docker-a", Address: "10.0.0.21", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	hostB, err := db.CreateHost(store.Host{
		Name: "no-docker-b", Address: "10.0.0.22", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := db.CreateMonitor(store.Monitor{
		Name: "Docker health", Type: "docker.health", IntervalSeconds: 60,
		RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		Assignments: []store.MonitorAssignment{{Scope: "fleet", Target: ""}},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, host := range []store.Host{hostA, hostB} {
		if err := db.UpsertMonitorState(store.MonitorState{
			MonitorID: monitor.ID, HostID: host.ID, Status: "unknown",
			Message: "Docker inventory is stale", CheckedAt: now, ChangedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := json.Marshal(map[string]any{
		"name": "Docker health", "type": "docker.health", "target": "",
		"interval_seconds": 60, "repeat_minutes": 60, "cooldown_minutes": 15,
		"enabled": true, "assignments": []map[string]any{{"scope": "host", "target": hostA.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodPut, ts.URL+"/api/v1/monitors/"+monitor.ID, "test-token", string(payload))
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("update monitor failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	if _, err := db.GetMonitorState(monitor.ID, hostB.ID); err == nil {
		t.Fatal("expected removed host state to be deleted")
	}
	if _, err := db.GetMonitorState(monitor.ID, hostA.ID); err != nil {
		t.Fatalf("expected assigned host state to remain: %v", err)
	}

	resp = request(t, http.MethodGet, ts.URL+"/api/v1/monitors", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list monitors failed: %d", resp.StatusCode)
	}
	var listed struct {
		Monitors []store.Monitor `json:"monitors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for _, entry := range listed.Monitors {
		if entry.ID != monitor.ID {
			continue
		}
		if len(entry.States) != 1 || entry.States[0].HostID != hostA.ID {
			t.Fatalf("expected only the assigned host state in the API response, got %+v", entry.States)
		}
		return
	}
	t.Fatal("updated monitor not found in list response")
}

func TestMonitorCapabilitySkip(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"docker":{"available":false},"systemd":{"available":false,"units_collected":false}}`); err != nil {
		t.Fatal(err)
	}
	dockerResult := app.evaluateDocker(store.Monitor{Type: "docker.project", Target: "app"}, host)
	if !dockerResult.skip {
		t.Fatalf("expected Docker capability skip, got %+v", dockerResult)
	}
	serviceResult := app.evaluateService(store.Monitor{Type: "service.systemd", Target: "nginx.service"}, host)
	if !serviceResult.skip {
		t.Fatalf("expected systemd capability skip, got %+v", serviceResult)
	}
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"docker":{"available":true},"systemd":{"available":true,"units_collected":true}}`); err != nil {
		t.Fatal(err)
	}
	dockerResult = app.evaluateDocker(store.Monitor{Type: "docker.project", Target: "app"}, host)
	if dockerResult.skip {
		t.Fatal("Docker monitor should evaluate when Docker is available")
	}
	if err := db.SaveServiceState(host.ID, nil, []string{"nginx.service"}); err != nil {
		t.Fatal(err)
	}
	serviceResult = app.evaluateService(store.Monitor{Type: "service.systemd", Target: "nginx.service"}, host)
	if serviceResult.skip || serviceResult.status != "ok" {
		t.Fatalf("expected running service, got %+v", serviceResult)
	}
}

func TestServiceBaselineMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"systemd":{"available":true,"units_collected":true}}`); err != nil {
		t.Fatal(err)
	}
	units := []string{"ssh.service", "cron.service"}
	if err := db.SaveServiceState(host.ID, nil, units); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureServiceBaseline(host.ID, units); err != nil {
		t.Fatal(err)
	}
	result := app.evaluateServiceBaseline(host)
	if result.status != "ok" {
		t.Fatalf("expected healthy baseline, got %+v", result)
	}

	if err := db.SaveServiceState(host.ID, []string{"cron.service"}, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "critical" || !strings.Contains(result.message, "cron.service") {
		t.Fatalf("expected failed service alert, got %+v", result)
	}

	if err := db.SaveServiceState(host.ID, nil, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "critical" || !strings.Contains(result.message, "cron.service") {
		t.Fatalf("expected missing baseline service alert, got %+v", result)
	}

	if err := db.SetServiceBaselineExcluded(host.ID, "cron.service", true); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "ok" {
		t.Fatalf("expected excluded service to be ignored, got %+v", result)
	}

	if err := db.SetSetting("host:"+host.ID, "monitor.service_baseline.enabled", "0"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "ok" || !strings.Contains(result.message, "disabled") {
		t.Fatalf("expected per-host baseline disable to suppress alerts, got %+v", result)
	}
}

func TestServiceBaselineFleetExclusion(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"systemd":{"available":true,"units_collected":true}}`); err != nil {
		t.Fatal(err)
	}
	units := []string{"ssh.service", "cron.service"}
	if err := db.SaveServiceState(host.ID, nil, units); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureServiceBaseline(host.ID, units); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveServiceState(host.ID, nil, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	result := app.evaluateServiceBaseline(host)
	if result.status != "critical" || !strings.Contains(result.message, "cron.service") {
		t.Fatalf("expected missing service alert before fleet exclusion, got %+v", result)
	}
	if err := db.SetSetting("fleet", "monitor.service_baseline.exclude", "cron.service"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "ok" {
		t.Fatalf("expected fleet-excluded missing service to be ignored, got %+v", result)
	}
	if err := db.SaveServiceState(host.ID, []string{"cron.service"}, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "ok" {
		t.Fatalf("expected fleet-excluded failed service to be ignored, got %+v", result)
	}
}

func TestServiceBaselineFleetPrefixExclusion(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"systemd":{"available":true,"units_collected":true}}`); err != nil {
		t.Fatal(err)
	}
	units := []string{"ssh.service", "volatile-agent@123.service"}
	if err := db.SaveServiceState(host.ID, nil, units); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureServiceBaseline(host.ID, units); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveServiceState(host.ID, nil, []string{"ssh.service"}); err != nil {
		t.Fatal(err)
	}
	result := app.evaluateServiceBaseline(host)
	if result.status != "critical" || !strings.Contains(result.message, "volatile-agent@123.service") {
		t.Fatalf("expected missing dynamic service before prefix exclusion, got %+v", result)
	}
	if err := db.SetSetting("fleet", "monitor.service_baseline.exclude", "volatile-agent@*"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateServiceBaseline(host)
	if result.status != "ok" {
		t.Fatalf("expected fleet prefix exclusion to ignore dynamic service, got %+v", result)
	}
}

func TestParseUnitListPatterns(t *testing.T) {
	units, err := parseUnitList("nginx.service, check-mk-agent@*, volatile-agent@*")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nginx.service", "check-mk-agent@*", "volatile-agent@*"}
	if strings.Join(units, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected units: %v", units)
	}
	for _, value := range []string{"*", "bad;unit", "bad*unit"} {
		if _, err := parseUnitList(value); err == nil {
			t.Fatalf("expected invalid unit pattern %q to be rejected", value)
		}
	}
}

func TestNetworkMonitorValidation(t *testing.T) {
	ts, _ := testServer(t)
	valid := []string{
		`{"name":"WAN events","type":"syslog.event","target":"WAN down","warning":1,"critical":5,"interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
		`{"name":"SNMP poll","type":"snmp.poll","interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
		`{"name":"Uptime","type":"snmp.value","target":".1.3.6.1.2.1.1.3.0","warning":100,"critical":200,"interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
	}
	for _, payload := range valid {
		resp := request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token", payload)
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Fatalf("expected monitor creation for %s, got %d %s", payload, resp.StatusCode, raw)
		}
		_ = resp.Body.Close()
	}
	invalid := []string{
		`{"name":"Bad SNMP","type":"snmp.value","target":"not an oid","warning":1,"critical":2,"interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
		`{"name":"SNMP poll","type":"snmp.poll","target":"x","interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
		`{"name":"Bad syslog","type":"syslog.event","warning":0,"critical":5,"interval_seconds":60,"assignments":[{"scope":"fleet"}]}`,
	}
	for _, payload := range invalid {
		resp := request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token", payload)
		if resp.StatusCode != http.StatusBadRequest {
			_ = resp.Body.Close()
			t.Fatalf("expected monitor rejection for %s, got %d", payload, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestParseEventWindow(t *testing.T) {
	tests := []struct {
		raw    string
		window string
		hasCut bool
	}{
		{"", "all", false},
		{"all", "all", false},
		{"unknown", "all", false},
		{"24h", "24h", true},
		{"7d", "7d", true},
	}
	for _, test := range tests {
		window, since := parseEventWindow(test.raw)
		if window != test.window || (since != "") != test.hasCut {
			t.Fatalf("%q: got %q/%q, want %q (cutoff=%t)", test.raw, window, since, test.window, test.hasCut)
		}
		if since != "" {
			if _, err := time.Parse(time.RFC3339Nano, since); err != nil {
				t.Fatalf("%q: invalid cutoff %q: %v", test.raw, since, err)
			}
		}
	}
}

func TestEventsWindowSummaryAPI(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "udm", Address: "192.168.4.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	recent := now.Add(-time.Hour).Format(time.RFC3339Nano)
	old := now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if err := db.AddHostEvents(host.ID, []store.HostEvent{
		{EventID: "window-1", Source: "syslog", Category: "network_wan", Severity: "critical", Message: "WAN down", OccurredAt: recent},
		{EventID: "window-2", Source: "syslog", Category: "network_link", Severity: "warning", Message: "link down", OccurredAt: recent},
		{EventID: "window-3", Source: "syslog", Category: "syslog", Severity: "info", Message: "informational", OccurredAt: old},
	}); err != nil {
		t.Fatal(err)
	}
	type eventsResponse struct {
		Events   []store.HostEvent      `json:"events"`
		Summary  store.HostEventSummary `json:"summary"`
		Window   string                 `json:"window"`
		Severity string                 `json:"severity"`
	}
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/events?window=24h", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("events request failed: %d %s", resp.StatusCode, raw)
	}
	var recentResponse eventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&recentResponse); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if recentResponse.Window != "24h" || len(recentResponse.Events) != 2 ||
		recentResponse.Summary.Total != 2 || recentResponse.Summary.Critical != 1 ||
		recentResponse.Summary.Warning != 1 {
		t.Fatalf("unexpected 24h response: %+v", recentResponse)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/events?window=24h&severity=critical", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("filtered events request failed: %d", resp.StatusCode)
	}
	var filteredResponse eventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&filteredResponse); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if filteredResponse.Severity != "critical" || len(filteredResponse.Events) != 1 ||
		filteredResponse.Events[0].Severity != "critical" || filteredResponse.Summary.Total != 2 {
		t.Fatalf("unexpected filtered response: %+v", filteredResponse)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/events", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("default events request failed: %d", resp.StatusCode)
	}
	var allResponse eventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&allResponse); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if allResponse.Window != "all" || len(allResponse.Events) != 3 || allResponse.Summary.Total != 3 {
		t.Fatalf("unexpected default response: %+v", allResponse)
	}
}

func TestClearEventsAndAlertsAPI(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "udm", Address: "192.168.4.1", AuthType: "network",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	monitor, err := db.CreateMonitor(store.Monitor{
		Name: "clear-api", Type: "host.cpu", IntervalSeconds: 60, Enabled: true,
		Assignments: []store.MonitorAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddHostEvents(host.ID, []store.HostEvent{
		{EventID: "clear-api-1", Source: "syslog", Category: "network_wan", Severity: "critical", Message: "WAN down", OccurredAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAlertEvent(store.AlertEvent{
		MonitorID: monitor.ID, HostID: host.ID, Status: "critical", Subject: "WAN down",
		Detail: "WAN down", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodDelete, ts.URL+"/api/v1/events", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("clear events failed: %d %s", resp.StatusCode, raw)
	}
	var cleared struct {
		Deleted int64 `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cleared); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if cleared.Deleted != 1 {
		t.Fatalf("expected one deleted event, got %d", cleared.Deleted)
	}
	if events, err := db.ListHostEvents(10); err != nil || len(events) != 0 {
		t.Fatalf("events after clear: %+v %v", events, err)
	}
	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/alerts", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("clear alerts failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if alerts, err := db.ListAlertEvents(10); err != nil || len(alerts) != 0 {
		t.Fatalf("alerts after clear: %+v %v", alerts, err)
	}
}

func TestHTTPMonitorInsecureSkipVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	monitor := store.Monitor{Type: "http", Target: server.URL}
	result := evaluateHTTP(context.Background(), monitor)
	if result.status != "critical" || !strings.Contains(strings.ToLower(result.message), "certificate") {
		t.Fatalf("expected certificate verification failure, got %+v", result)
	}
	monitor.InsecureSkipVerify = true
	result = evaluateHTTP(context.Background(), monitor)
	if result.status != "ok" {
		t.Fatalf("expected insecure HTTP monitor to succeed, got %+v", result)
	}
}

func TestMonitorInsecureSkipVerifyValidation(t *testing.T) {
	ts, _ := testServer(t)
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token",
		`{"name":"NAS","type":"http","target":"https://192.168.6.20/cgi-bin/","interval_seconds":60,"insecure_skip_verify":true}`)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected HTTP monitor creation, got %d %s", resp.StatusCode, raw)
	}
	var created store.Monitor
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !created.InsecureSkipVerify {
		t.Fatal("expected insecure_skip_verify to be saved")
	}
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/monitors", "test-token",
		`{"name":"CPU","type":"host.cpu","warning":80,"critical":90,"interval_seconds":60,"insecure_skip_verify":true,"assignments":[{"scope":"fleet"}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		_ = resp.Body.Close()
		t.Fatalf("expected insecure flag rejection for non-HTTP monitor, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDockerAllContainersMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"docker":{"available":true}}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDockerInventory(host.ID, nil, []store.DockerContainer{
		{ContainerID: "c1", Name: "web-1", State: "running", Health: "healthy"},
		{ContainerID: "c2", Name: "job-1", State: "exited"},
	}); err != nil {
		t.Fatal(err)
	}
	result := app.evaluateDocker(store.Monitor{Type: "docker.container", Target: "*"}, host)
	if result.status != "critical" || !strings.Contains(result.message, "job-1") {
		t.Fatalf("expected all-container monitor to report stopped container, got %+v", result)
	}
	if err := db.SaveDockerInventory(host.ID, nil, []store.DockerContainer{
		{ContainerID: "c1", Name: "web-1", State: "running", Health: "healthy"},
	}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateDocker(store.Monitor{Type: "docker.container", Target: "*"}, host)
	if result.status != "ok" || !strings.Contains(result.message, "1/1") {
		t.Fatalf("expected all-container monitor to be healthy, got %+v", result)
	}
	if err := db.SetSetting("host:"+host.ID, "monitor.docker.enabled", "0"); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateDocker(store.Monitor{Type: "docker.container", Target: "*"}, host)
	if result.status != "ok" || !strings.Contains(result.message, "disabled") {
		t.Fatalf("expected per-host Docker disable to suppress container alerts, got %+v", result)
	}
	health := app.evaluateDockerHealth(host)
	if health.status != "ok" || !strings.Contains(health.message, "disabled") {
		t.Fatalf("expected per-host Docker disable to suppress health alerts, got %+v", health)
	}
}

func TestServiceBaselineAPI(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{
		Name: "web01", Address: "10.0.0.11", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/tmp/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveServiceState(host.ID, nil, []string{"ssh.service", "packagekit.service"}); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureServiceBaseline(host.ID, []string{"ssh.service", "packagekit.service"}); err != nil {
		t.Fatal(err)
	}

	resp := request(t, http.MethodGet, ts.URL+"/api/v1/hosts/"+host.ID+"/service-baseline", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected baseline GET, got %d", resp.StatusCode)
	}
	var view serviceBaselineView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(view.Baseline) != 2 || len(view.Current) != 2 || !view.Enabled || !view.AutoAdd {
		t.Fatalf("unexpected baseline view: %+v", view)
	}

	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID+"/service-baseline/packagekit.service",
		"test-token", `{"excluded":true}`)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected baseline exclude, got %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	baseline, err := db.ListServiceBaseline(host.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range baseline {
		if item.Unit == "packagekit.service" && !item.Excluded {
			t.Fatalf("expected packagekit.service to be excluded: %+v", item)
		}
	}

	resp = request(t, http.MethodPost, ts.URL+"/api/v1/hosts/"+host.ID+"/service-baseline/reset", "test-token", `{}`)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected baseline reset, got %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()

	resp = request(t, http.MethodPut, ts.URL+"/api/v1/hosts/"+host.ID+"/service-baseline/not-tracked.service",
		"test-token", `{"excluded":false}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected missing baseline include to return 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDockerHealthMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	if err := db.SaveSystemInfo(host.ID, time.Now().UTC().Format(time.RFC3339Nano),
		`{"docker":{"available":true}}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDockerInventory(host.ID, nil, []store.DockerContainer{
		{ContainerID: "c1", Name: "web-1", State: "running", Health: "unhealthy"},
	}); err != nil {
		t.Fatal(err)
	}
	result := app.evaluateDockerHealth(host)
	if result.status != "critical" || !strings.Contains(result.message, "web-1") {
		t.Fatalf("expected unhealthy container alert, got %+v", result)
	}

	if err := db.SaveDockerInventory(host.ID, nil, []store.DockerContainer{
		{ContainerID: "c1", Name: "web-1", State: "running", Health: "healthy"},
	}); err != nil {
		t.Fatal(err)
	}
	result = app.evaluateDockerHealth(host)
	if result.status != "ok" {
		t.Fatalf("expected healthy container state, got %+v", result)
	}
}

func TestNTPMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	monitor := store.Monitor{Type: "host.ntp", Warning: 1, Critical: 5}
	save := func(sync bool, offset float64) store.Host {
		facts := store.Facts{
			CollectedAt: time.Now().UTC().Format(time.RFC3339Nano),
			TimeSyncOK:  sync, TimeSyncSource: "timedatectl",
			TimeSyncOffset: offset, TimeSyncOffsetKnown: true,
		}
		if err := db.SaveFactsAs("test", host.ID, facts); err != nil {
			t.Fatal(err)
		}
		updated, err := db.GetHost(host.ID)
		if err != nil {
			t.Fatal(err)
		}
		return updated
	}
	result := app.evaluateNTP(monitor, save(true, 0.1))
	if result.status != "ok" {
		t.Fatalf("expected synchronized clock, got %+v", result)
	}
	result = app.evaluateNTP(monitor, save(true, 2))
	if result.status != "warning" {
		t.Fatalf("expected warning offset, got %+v", result)
	}
	result = app.evaluateNTP(monitor, save(true, 6))
	if result.status != "critical" {
		t.Fatalf("expected critical offset, got %+v", result)
	}
	result = app.evaluateNTP(monitor, save(false, 0))
	if result.status != "critical" || !strings.Contains(result.message, "not synchronized") {
		t.Fatalf("expected unsynchronized clock, got %+v", result)
	}
}

func TestSecurityAuthMonitor(t *testing.T) {
	app, db, host := newMonitorTestApp(t)
	monitor := store.Monitor{Type: "security.auth", Warning: 5, Critical: 10}
	next := 0
	add := func(count int) {
		events := make([]store.HostEvent, 0, count)
		for index := 0; index < count; index++ {
			events = append(events, store.HostEvent{
				EventID: "event-" + strconv.Itoa(next), Source: "ssh.service",
				Category: "auth_failure", Severity: "warning",
				OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
			})
			next++
		}
		if err := db.AddHostEvents(host.ID, events); err != nil {
			t.Fatal(err)
		}
	}
	add(0)
	if result := app.evaluateAuthFailures(monitor, host); result.status != "ok" {
		t.Fatalf("expected ok, got %+v", result)
	}
	add(6)
	if result := app.evaluateAuthFailures(monitor, host); result.status != "warning" {
		t.Fatalf("expected warning, got %+v", result)
	}
	add(5)
	if result := app.evaluateAuthFailures(monitor, host); result.status != "critical" {
		t.Fatalf("expected critical, got %+v", result)
	}
}

func TestMonitorSeverityRecipients(t *testing.T) {
	app, db, _ := newMonitorTestApp(t)
	for key, value := range map[string]string{
		"recipients":          "global@example.com",
		"warning_recipients":  "warning@example.com",
		"critical_recipients": "critical@example.com",
		"recovery_recipients": "recovery@example.com",
	} {
		if err := db.SetSetting("smtp", key, value); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := app.loadSMTPConfig()
	if err != nil {
		t.Fatal(err)
	}
	monitor := store.Monitor{}
	cases := []struct {
		status   string
		recovery bool
		want     string
	}{
		{"warning", false, "warning@example.com"},
		{"critical", false, "critical@example.com"},
		{"ok", true, "recovery@example.com"},
		{"ok", false, "global@example.com"},
	}
	for _, tc := range cases {
		got, err := app.monitorRecipients(cfg, monitor, tc.status, tc.recovery)
		if err != nil || len(got) != 1 || got[0] != tc.want {
			t.Fatalf("%s recovery=%v: got %v err=%v", tc.status, tc.recovery, got, err)
		}
	}
	override := store.Monitor{Recipients: "override@example.com"}
	got, err := app.monitorRecipients(cfg, override, "critical", false)
	if err != nil || len(got) != 1 || got[0] != "override@example.com" {
		t.Fatalf("monitor override not honored: %v err=%v", got, err)
	}
}
