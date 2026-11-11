package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestResolveMonitorTargets(t *testing.T) {
	hosts := map[string]store.Host{
		"a": {ID: "a", Name: "web01", GroupName: "web", Tags: "prod,web"},
		"b": {ID: "b", Name: "web02", GroupName: "web", Tags: "test"},
		"c": {ID: "c", Name: "db01", GroupName: "db", Tags: "prod"},
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
	targets, active, network = resolveMonitorTargets("http", []store.MonitorAssignment{{Scope: "fleet"}}, hosts)
	if !active || !network || len(targets) != 0 {
		t.Fatalf("network targets: %+v active=%v network=%v", targets, active, network)
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
