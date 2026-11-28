package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

func TestSyslogPolicyClassifiesAndSuppresses(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	if _, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "noise marker", Scope: "fleet", MatchType: "contains",
		Pattern: "noise marker", Category: "test_noise", Severity: "info",
		Suppress: true, Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm app: noise marker`)
	all, err := db.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(all) != 1 {
		t.Fatalf("events: %+v %v", all, err)
	}
	event := all[0]
	if event.Category != "test_noise" || event.Severity != "info" || !event.Suppressed ||
		event.OriginalCategory != "syslog" || event.OriginalSeverity != "warning" ||
		event.PolicyName != "noise marker" || event.Guardrail {
		t.Fatalf("unexpected policy event: %+v", event)
	}
	visible, err := db.ListHostEvents(10)
	if err != nil || len(visible) != 0 {
		t.Fatalf("suppressed event must be hidden by default: %+v %v", visible, err)
	}
	summary, err := db.SummarizeHostEvents("")
	if err != nil || summary.Total != 0 || summary.Suppressed != 1 {
		t.Fatalf("unexpected summary: %+v %v", summary, err)
	}
}

func TestSyslogPolicyHostScopeOverridesFleet(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	udm, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"})
	if err != nil {
		t.Fatal(err)
	}
	ap, err := db.CreateHost(store.Host{Name: "ap", Address: "10.0.0.51", AuthType: "network"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "fleet noise", Scope: "fleet", MatchType: "contains", Pattern: "scope marker",
		Category: "fleet_noise", Severity: "info", Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "ap noise", Scope: "host", HostID: udm.ID, MatchType: "contains", Pattern: "scope marker",
		Category: "host_noise", Severity: "warning", Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm app: scope marker one`)
	app.handleSyslogMessage("10.0.0.51", `<12>Nov 28 01:00:01 ap app: scope marker two`)
	events, err := db.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v %v", events, err)
	}
	categories := map[string]string{}
	for _, event := range events {
		categories[event.HostID] = event.Category
	}
	if categories[udm.ID] != "host_noise" || categories[ap.ID] != "fleet_noise" {
		t.Fatalf("unexpected host scope categories: %+v", categories)
	}
}

func TestSyslogPolicyGuardrailsCriticalAuth(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	if _, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "hide login", Scope: "fleet", MatchType: "contains", Pattern: "Failed password",
		Category: "syslog", Severity: "info", Suppress: true, Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm sshd: Failed password for admin`)
	all, err := db.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(all) != 1 {
		t.Fatalf("events: %+v %v", all, err)
	}
	event := all[0]
	if event.Category != "auth_failure" || event.Severity != "critical" || event.Suppressed || !event.Guardrail {
		t.Fatalf("auth guardrail failed: %+v", event)
	}
	if event.PolicyName != "hide login" {
		t.Fatalf("expected attempted policy metadata: %+v", event)
	}
}

func TestSyslogPolicyGuardrailsProtectedKernel(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	if _, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "hide kernel", Scope: "fleet", MatchType: "contains", Pattern: "kernel:",
		Category: "syslog", Severity: "info", Suppress: true, Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm kernel: I/O error on nvme0n1`)
	all, err := db.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(all) != 1 {
		t.Fatalf("events: %+v %v", all, err)
	}
	event := all[0]
	if event.Severity != "critical" || event.Suppressed || !event.Guardrail {
		t.Fatalf("kernel guardrail failed: %+v", event)
	}
}

func TestSyslogPolicyGuardrailsCriticalNetworkEvent(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	if _, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "downgrade WAN", Scope: "fleet", MatchType: "contains", Pattern: "WAN down",
		Category: "syslog", Severity: "info", Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm app: WAN down`)
	all, err := db.ListHostEventsFilteredIncludingSuppressed(10, "", "", true)
	if err != nil || len(all) != 1 {
		t.Fatalf("events: %+v %v", all, err)
	}
	event := all[0]
	if event.Category != "network_wan" || event.Severity != "critical" || !event.Guardrail {
		t.Fatalf("critical guardrail failed: %+v", event)
	}
}

func TestSyslogPolicyValidationRejectsDangerousSuppression(t *testing.T) {
	ts, _ := testServer(t)
	payloads := []string{
		`{"name":"all","scope":"fleet","match_type":"regex","pattern":".*","suppress":true,"enabled":true}`,
		`{"name":"kernel","scope":"fleet","match_type":"contains","pattern":"kernel:","suppress":true,"enabled":true}`,
		`{"name":"kernel-info","scope":"fleet","match_type":"contains","pattern":"kernel:","severity":"info","suppress":false,"enabled":true}`,
		`{"name":"all-info","scope":"fleet","match_type":"regex","pattern":".*","severity":"info","suppress":false,"enabled":true}`,
		`{"name":"kernel-regex","scope":"fleet","match_type":"regex","pattern":"(?i:kernel)","suppress":true,"enabled":true}`,
		`{"name":"empty-regex","scope":"fleet","match_type":"regex","pattern":"(?i)","category":"syslog","enabled":true}`,
		`{"name":"short","scope":"fleet","match_type":"contains","pattern":"ab","suppress":true,"enabled":true}`,
		`{"name":"auth","scope":"fleet","match_type":"contains","pattern":"login","category":"auth_failure","suppress":true,"enabled":true}`,
		`{"name":"critical","scope":"fleet","match_type":"contains","pattern":"noise","severity":"critical","suppress":true,"enabled":true}`,
	}
	for _, payload := range payloads {
		resp := request(t, http.MethodPost, ts.URL+"/api/v1/syslog/policies", "test-token", payload)
		if resp.StatusCode != http.StatusBadRequest {
			_ = resp.Body.Close()
			t.Fatalf("expected unsafe suppression rejection for %s, got %d", payload, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestSyslogPolicyRegexAndDisabled(t *testing.T) {
	_, db, app := testServerWithApp(t, true)
	if _, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateSyslogPolicy(store.SyslogPolicy{
		Name: "regex", Scope: "fleet", MatchType: "regex", Pattern: `noise\s+marker`,
		Category: "regex_noise", Severity: "info", Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:00 udm app: noise   marker`)
	events, err := db.ListHostEvents(10)
	if err != nil || len(events) != 1 || events[0].Category != "regex_noise" {
		t.Fatalf("regex policy failed: %+v %v", events, err)
	}
	policies, err := db.ListSyslogPolicies()
	if err != nil || len(policies) != 1 {
		t.Fatalf("policies: %+v %v", policies, err)
	}
	disabled := policies[0]
	disabled.Enabled = false
	if err := db.UpdateSyslogPolicy(disabled); err != nil {
		t.Fatal(err)
	}
	app.invalidateSyslogPolicyCache()
	app.handleSyslogMessage("10.0.0.50", `<12>Nov 28 01:00:01 udm app: noise marker two`)
	events, err = db.ListHostEvents(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events: %+v %v", events, err)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "two") && event.Category == "regex_noise" {
			t.Fatalf("disabled policy applied: %+v", event)
		}
	}
}

func TestSyslogPolicyAPIAndPreview(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddHostEvents(host.ID, []store.HostEvent{{
		EventID: "preview-1", Source: "syslog", Category: "syslog", Severity: "warning",
		Message: "app: noise marker", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}}); err != nil {
		t.Fatal(err)
	}
	payload := `{"name":"Noise","description":"test","scope":"fleet","match_type":"contains","pattern":"noise marker","category":"test_noise","severity":"info","suppress":true,"priority":10,"enabled":true}`
	resp := request(t, http.MethodPost, ts.URL+"/api/v1/syslog/policies", "test-token", payload)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("create policy failed: %d %s", resp.StatusCode, raw)
	}
	var created store.SyslogPolicy
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/syslog/policies", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("list policies failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	preview := `{"name":"Noise preview","scope":"fleet","match_type":"contains","pattern":"noise marker","category":"test_noise","severity":"info","suppress":true,"priority":10,"enabled":true,"window":"all","limit":100}`
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/syslog/policies/preview", "test-token", preview)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("preview failed: %d %s", resp.StatusCode, raw)
	}
	var result struct {
		Matched       int `json:"matched"`
		WouldSuppress int `json:"would_suppress"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if result.Matched != 1 || result.WouldSuppress != 1 {
		t.Fatalf("unexpected preview: %+v", result)
	}
	update := `{"name":"Noise updated","scope":"fleet","match_type":"contains","pattern":"noise marker","category":"test_noise","severity":"warning","suppress":false,"priority":20,"enabled":true}`
	resp = request(t, http.MethodPut, ts.URL+"/api/v1/syslog/policies/"+created.ID, "test-token", update)
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("update policy failed: %d %s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()
	resp = request(t, http.MethodDelete, ts.URL+"/api/v1/syslog/policies/"+created.ID, "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("delete policy failed: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	resp = request(t, http.MethodPost, ts.URL+"/api/v1/syslog/policies", "test-token",
		`{"name":"Bad regex","scope":"fleet","match_type":"regex","pattern":"[","severity":"info","enabled":true}`)
	if resp.StatusCode != http.StatusBadRequest {
		_ = resp.Body.Close()
		t.Fatalf("expected invalid regex rejection, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestEventsIncludeSuppressedAPI(t *testing.T) {
	ts, db := testServer(t)
	host, err := db.CreateHost(store.Host{Name: "udm", Address: "10.0.0.50", AuthType: "network"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddHostEvents(host.ID, []store.HostEvent{{
		EventID: "suppressed-api", Source: "syslog", Category: "syslog", Severity: "info",
		Message: "hidden", OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), Suppressed: true,
	}}); err != nil {
		t.Fatal(err)
	}
	resp := request(t, http.MethodGet, ts.URL+"/api/v1/events?window=all", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("events failed: %d", resp.StatusCode)
	}
	var hidden struct {
		Events  []store.HostEvent      `json:"events"`
		Summary store.HostEventSummary `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hidden); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(hidden.Events) != 0 || hidden.Summary.Suppressed != 1 {
		t.Fatalf("suppressed event leaked: %+v", hidden)
	}
	resp = request(t, http.MethodGet, ts.URL+"/api/v1/events?window=all&include_suppressed=1", "test-token", "")
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("events include failed: %d", resp.StatusCode)
	}
	var included struct {
		Events []store.HostEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&included); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(included.Events) != 1 || !included.Events[0].Suppressed {
		t.Fatalf("suppressed event missing after include: %+v", included)
	}
}
