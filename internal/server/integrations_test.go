package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmware/govmomi/simulator"
)

func TestVCenterPollWithSimulator(t *testing.T) {
	model := simulator.VPX()
	defer model.Remove()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	model.Service.TLS = new(tls.Config)
	server := model.Service.NewServer()
	defer server.Close()
	port := server.URL.Port()
	if port == "" {
		t.Fatal("simulator did not expose a port")
	}
	username := ""
	password := ""
	if server.URL.User != nil {
		username = server.URL.User.Username()
		password, _ = server.URL.User.Password()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	result, err := (&Server{}).pollVCenter(ctx, integrationConfig{
		URL:      "https://" + server.URL.Hostname() + ":" + port + "/sdk",
		Username: username, Password: password, Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Summary, "managed entities") {
		t.Fatalf("unexpected vCenter summary: %s", result.Summary)
	}
}

func TestHAProxyStatsPoll(t *testing.T) {
	csvBody := `# pxname,svname,qcur,status,check_status,check_code,addr,lastchg
web,FRONTEND,,OPEN,,,,,
web,BACKEND,,UP,,,,,
web,app1,,UP,L4OK,0,10.0.0.1:80,10
web,app2,,DOWN,L4CON,0,10.0.0.2:80,20
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ";csv") {
			_, _ = io.WriteString(w, csvBody)
			return
		}
		_, _ = io.WriteString(w, "<html><body>stats</body></html>")
	}))
	defer server.Close()
	app := &Server{}
	result, err := app.pollHAProxy(context.Background(), integrationConfig{URL: server.URL + "/stats"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Status != "critical" {
		t.Fatalf("unexpected findings: %+v", result)
	}
	if !strings.Contains(result.Findings[0].Subject, "web/app2") {
		t.Fatalf("unexpected subject: %+v", result.Findings[0])
	}
	if !strings.Contains(result.Summary, "1 backends") {
		t.Fatalf("unexpected summary: %s", result.Summary)
	}
}

func TestOPNsenseGatewayPoll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/routes/gateway/status" {
			http.NotFound(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "key" || pass != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[
			{"name":"WAN","address":"192.0.2.1","status":"none","delay":"2.1 ms","loss":"0.0 %","stddev":"0.2 ms"},
			{"name":"LTE","address":"192.0.2.2","status":"loss","delay":"30 ms","loss":"12.5 %","stddev":"4 ms"},
			{"name":"BACKUP","address":"192.0.2.3","status":"down","delay":"","loss":"100 %","stddev":""}
		]`)
	}))
	defer server.Close()
	app := &Server{}
	result, err := app.pollOPNsense(context.Background(), integrationConfig{
		URL: server.URL, APIKey: "key", APISecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("unexpected findings: %+v", result)
	}
	statuses := map[string]string{}
	for _, finding := range result.Findings {
		statuses[finding.Key] = finding.Status
	}
	if statuses["LTE"] != "warning" || statuses["BACKUP"] != "critical" {
		t.Fatalf("unexpected gateway statuses: %+v", statuses)
	}
	if !strings.Contains(result.Summary, "3 gateways") {
		t.Fatalf("unexpected summary: %s", result.Summary)
	}
}

func TestIntegrationFindingsStateAndRecovery(t *testing.T) {
	app, db, _ := newMonitorTestApp(t)
	cfg := integrationConfig{Source: integrationHAProxy}
	now := time.Now().UTC()
	finding := integrationFinding{Key: "web/app1", Status: "critical", Subject: "HAProxy server down - web/app1", Detail: "status=DOWN"}
	app.processIntegrationFindings(cfg, []integrationFinding{finding}, now)
	events, err := db.ListIntegrationEvents(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("expected first integration event, got %+v %v", events, err)
	}
	if events[0].Emailed || events[0].Error == "" {
		t.Fatalf("expected recorded email failure: %+v", events[0])
	}
	state, err := db.GetIntegrationState("haproxy", "web/app1")
	if err != nil || state.Status != "critical" {
		t.Fatalf("state: %+v %v", state, err)
	}

	app.processIntegrationFindings(cfg, []integrationFinding{finding}, now.Add(time.Minute))
	events, _ = db.ListIntegrationEvents(10)
	if len(events) != 1 {
		t.Fatalf("unchanged finding should not create another event, got %d", len(events))
	}

	warning := integrationFinding{Key: "web/app1", Status: "warning", Subject: "HAProxy server degraded - web/app1", Detail: "status=NOLB"}
	app.processIntegrationFindings(cfg, []integrationFinding{warning}, now.Add(2*time.Minute))
	events, _ = db.ListIntegrationEvents(10)
	if len(events) != 2 || events[0].Status != "warning" {
		t.Fatalf("expected severity transition event, got %+v", events)
	}
	app.processIntegrationFindings(cfg, []integrationFinding{warning}, now.Add(3*time.Minute))
	events, _ = db.ListIntegrationEvents(10)
	if len(events) != 2 {
		t.Fatalf("unchanged warning should not create another event, got %d", len(events))
	}

	app.processIntegrationFindings(cfg, nil, now.Add(4*time.Minute))
	events, _ = db.ListIntegrationEvents(10)
	if len(events) != 3 || events[0].Status != "ok" {
		t.Fatalf("expected recovery event, got %+v", events)
	}
	states, err := db.ListIntegrationStates("haproxy")
	if err != nil || len(states) != 0 {
		t.Fatalf("expected no active states, got %+v %v", states, err)
	}
}

func TestIntegrationConfigMaskingAndValidation(t *testing.T) {
	ts, _ := testServer(t)
	base := ts.URL
	payload := `{"enabled":true,"url":"http://haproxy.example.com/stats","username":"stats","password":"super-secret","poll_seconds":60,"recipients":"ops@example.com"}`
	resp := request(t, http.MethodPut, base+"/api/v1/integrations/haproxy", "test-token", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save integration failed: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "super-secret") {
		t.Fatal("integration password was returned by the API")
	}
	resp = request(t, http.MethodGet, base+"/api/v1/integrations", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "super-secret") || !strings.Contains(string(body), `"password_set":true`) {
		t.Fatalf("unexpected integration list response: %s", body)
	}

	// A blank password on update must retain the stored secret.
	resp = request(t, http.MethodPut, base+"/api/v1/integrations/haproxy", "test-token",
		`{"enabled":true,"url":"http://haproxy.example.com/stats","username":"stats","password":"","poll_seconds":60}`)
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("update integration failed: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()
	resp = request(t, http.MethodGet, base+"/api/v1/integrations/haproxy", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"password_set":true`) {
		t.Fatalf("stored integration password was not retained: %s", body)
	}

	resp = request(t, http.MethodPut, base+"/api/v1/integrations/vcenter", "test-token",
		`{"enabled":true,"url":"http://vcenter.example.com","username":"readonly","password":"secret","poll_seconds":30}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected vCenter HTTPS validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodPut, base+"/api/v1/integrations/opnsense", "test-token",
		`{"enabled":true,"url":"https://fw.example.com","poll_seconds":60}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected OPNsense credential validation failure, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	resp = request(t, http.MethodPost, base+"/api/v1/integrations/opnsense/check", "test-token", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected disabled integration check rejection, got %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	var list struct {
		Integrations []integrationView `json:"integrations"`
	}
	resp = request(t, http.MethodGet, base+"/api/v1/integrations", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Integrations) != 3 {
		t.Fatalf("expected three integration views, got %+v", list.Integrations)
	}
}
