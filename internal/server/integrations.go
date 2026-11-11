package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/store"
)

const (
	integrationVCenter = "vcenter"
	integrationHAProxy = "haproxy"
	integrationOPN     = "opnsense"
)

var integrationOrder = []string{integrationVCenter, integrationHAProxy, integrationOPN}

type integrationMeta struct {
	label       string
	defaultPoll int
	minPoll     int
}

var integrationSources = map[string]integrationMeta{
	integrationVCenter: {label: "vCenter", defaultPoll: 30, minPoll: 30},
	integrationHAProxy: {label: "HAProxy", defaultPoll: 60, minPoll: 15},
	integrationOPN:     {label: "OPNsense", defaultPoll: 60, minPoll: 15},
}

type integrationConfig struct {
	Source      string
	Enabled     bool
	URL         string
	Username    string
	Password    string
	APIKey      string
	APISecret   string
	Insecure    bool
	PollSeconds int
	Recipients  string
}

type integrationRequest struct {
	Enabled          bool   `json:"enabled"`
	URL              string `json:"url"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	ClearCredentials bool   `json:"clear_credentials"`
	APIKey           string `json:"api_key"`
	APISecret        string `json:"api_secret"`
	Insecure         bool   `json:"insecure_skip_verify"`
	PollSeconds      int    `json:"poll_seconds"`
	Recipients       string `json:"recipients"`
}

type integrationView struct {
	Source       string `json:"source"`
	Label        string `json:"label"`
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	PasswordSet  bool   `json:"password_set"`
	APIKeySet    bool   `json:"api_key_set"`
	APISecretSet bool   `json:"api_secret_set"`
	Insecure     bool   `json:"insecure_skip_verify"`
	PollSeconds  int    `json:"poll_seconds"`
	Recipients   string `json:"recipients"`
	LastPolledAt string `json:"last_polled_at"`
	LastError    string `json:"last_error"`
	LastSummary  string `json:"last_summary"`
}

type integrationRuntime struct {
	lastPolledAt string
	lastError    string
	lastSummary  string
}

type integrationFinding struct {
	Key     string
	Status  string
	Subject string
	Detail  string
}

type integrationPollResult struct {
	Summary  string
	Findings []integrationFinding
}

func integrationMetaFor(source string) (integrationMeta, bool) {
	meta, ok := integrationSources[source]
	return meta, ok
}

func integrationScope(source string) string {
	return "integration:" + source
}

func boolValue(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func (s *Server) loadIntegrationConfig(source string) (integrationConfig, error) {
	meta, ok := integrationMetaFor(source)
	if !ok {
		return integrationConfig{}, errors.New("unknown integration")
	}
	settings, err := s.store.ListSettings(integrationScope(source))
	if err != nil {
		return integrationConfig{}, err
	}
	cfg := integrationConfig{
		Source:      source,
		Enabled:     settings["enabled"] == "1",
		URL:         strings.TrimSpace(settings["url"]),
		Username:    strings.TrimSpace(settings["username"]),
		Password:    settings["password"],
		APIKey:      settings["api_key"],
		APISecret:   settings["api_secret"],
		Insecure:    settings["insecure_skip_verify"] == "1",
		PollSeconds: meta.defaultPoll,
		Recipients:  settings["recipients"],
	}
	if value, err := strconv.Atoi(settings["poll_seconds"]); err == nil && value > 0 {
		cfg.PollSeconds = value
	}
	return cfg, nil
}

func (s *Server) saveIntegrationConfig(source string, request integrationRequest) (integrationConfig, error) {
	meta, ok := integrationMetaFor(source)
	if !ok {
		return integrationConfig{}, errors.New("unknown integration")
	}
	existing, err := s.loadIntegrationConfig(source)
	if err != nil {
		return integrationConfig{}, err
	}
	cfg := integrationConfig{
		Source:      source,
		Enabled:     request.Enabled,
		URL:         strings.TrimSpace(request.URL),
		Username:    strings.TrimSpace(request.Username),
		Password:    existing.Password,
		APIKey:      existing.APIKey,
		APISecret:   existing.APISecret,
		Insecure:    request.Insecure,
		PollSeconds: request.PollSeconds,
		Recipients:  strings.TrimSpace(request.Recipients),
	}
	if cfg.PollSeconds <= 0 {
		cfg.PollSeconds = meta.defaultPoll
	}
	if request.Password != "" {
		cfg.Password = request.Password
	}
	if request.APIKey != "" {
		cfg.APIKey = request.APIKey
	}
	if request.APISecret != "" {
		cfg.APISecret = request.APISecret
	}
	if request.ClearCredentials {
		cfg.Password = ""
		cfg.APIKey = ""
		cfg.APISecret = ""
	}
	if source != integrationOPN && cfg.Username == "" {
		cfg.Password = ""
	}
	if source == integrationOPN {
		cfg.Username = ""
		cfg.Password = ""
	} else {
		cfg.APIKey = ""
		cfg.APISecret = ""
	}
	if err := validateIntegrationConfig(cfg, cfg.Enabled); err != nil {
		return integrationConfig{}, err
	}
	scope := integrationScope(source)
	values := map[string]string{
		"enabled":              boolValue(cfg.Enabled),
		"url":                  cfg.URL,
		"username":             cfg.Username,
		"insecure_skip_verify": boolValue(cfg.Insecure),
		"poll_seconds":         strconv.Itoa(cfg.PollSeconds),
		"recipients":           cfg.Recipients,
	}
	if cfg.Password != "" {
		values["password"] = cfg.Password
	}
	if cfg.APIKey != "" {
		values["api_key"] = cfg.APIKey
	}
	if cfg.APISecret != "" {
		values["api_secret"] = cfg.APISecret
	}
	for key, value := range values {
		if err := s.store.SetSetting(scope, key, value); err != nil {
			return integrationConfig{}, err
		}
	}
	for _, key := range []string{"password", "api_key", "api_secret"} {
		if (key == "password" && cfg.Password == "") || (key == "api_key" && cfg.APIKey == "") || (key == "api_secret" && cfg.APISecret == "") {
			if err := s.store.DeleteSetting(scope, key); err != nil {
				return integrationConfig{}, err
			}
		}
	}
	return cfg, nil
}

func validateIntegrationConfig(cfg integrationConfig, requireComplete bool) error {
	meta, ok := integrationMetaFor(cfg.Source)
	if !ok {
		return errors.New("unknown integration")
	}
	if cfg.PollSeconds < meta.minPoll || cfg.PollSeconds > 3600 {
		return fmt.Errorf("poll_seconds must be between %d and 3600", meta.minPoll)
	}
	if strings.TrimSpace(cfg.Recipients) != "" {
		if _, err := mailer.ParseRecipients(cfg.Recipients); err != nil {
			return err
		}
	}
	if cfg.URL != "" {
		parsed, err := url.Parse(cfg.URL)
		if err != nil || parsed.Host == "" {
			return errors.New("url must be an absolute URL")
		}
		if parsed.User != nil {
			return errors.New("put credentials in the dedicated fields, not in the URL")
		}
		if cfg.Source == integrationVCenter {
			if parsed.Scheme != "https" {
				return errors.New("vCenter URL must use https")
			}
		} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("url must use http or https")
		}
	}
	if !requireComplete {
		return nil
	}
	switch cfg.Source {
	case integrationVCenter:
		if !strings.HasPrefix(cfg.URL, "https://") {
			return errors.New("vCenter URL is required and must use https")
		}
		if cfg.Username == "" || cfg.Password == "" {
			return errors.New("vCenter username and password are required")
		}
	case integrationHAProxy:
		if cfg.URL == "" {
			return errors.New("HAProxy stats URL is required")
		}
		if cfg.Username != "" && cfg.Password == "" {
			return errors.New("HAProxy password is required when a username is set")
		}
	case integrationOPN:
		if cfg.URL == "" {
			return errors.New("OPNsense URL is required")
		}
		if cfg.APIKey == "" || cfg.APISecret == "" {
			return errors.New("OPNsense API key and secret are required")
		}
	default:
		return errors.New("unknown integration")
	}
	return nil
}

func (s *Server) integrationView(source string) (integrationView, error) {
	cfg, err := s.loadIntegrationConfig(source)
	if err != nil {
		return integrationView{}, err
	}
	meta := integrationSources[source]
	view := integrationView{
		Source: source, Label: meta.label, Enabled: cfg.Enabled, URL: cfg.URL,
		Username: cfg.Username, PasswordSet: cfg.Password != "", APIKeySet: cfg.APIKey != "",
		APISecretSet: cfg.APISecret != "", Insecure: cfg.Insecure, PollSeconds: cfg.PollSeconds,
		Recipients: cfg.Recipients,
	}
	s.integrationMu.Lock()
	runtime := s.integrationRuntime[source]
	s.integrationMu.Unlock()
	view.LastPolledAt = runtime.lastPolledAt
	view.LastError = runtime.lastError
	view.LastSummary = runtime.lastSummary
	return view, nil
}

func (s *Server) integrationHTTPClient(insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}
}

func (s *Server) markIntegrationAttempt(source string, at time.Time) {
	s.integrationMu.Lock()
	defer s.integrationMu.Unlock()
	runtime := s.integrationRuntime[source]
	runtime.lastPolledAt = at.Format(time.RFC3339)
	s.integrationRuntime[source] = runtime
}

func (s *Server) markIntegrationResult(source string, pollErr error, summary string) {
	s.integrationMu.Lock()
	defer s.integrationMu.Unlock()
	runtime := s.integrationRuntime[source]
	runtime.lastPolledAt = time.Now().UTC().Format(time.RFC3339)
	if pollErr != nil {
		runtime.lastError = pollErr.Error()
	} else {
		runtime.lastError = ""
		runtime.lastSummary = summary
	}
	s.integrationRuntime[source] = runtime
}

func (s *Server) RunIntegrations(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluateIntegrations(ctx)
		case <-s.integrationWake:
			s.evaluateIntegrations(ctx)
		}
	}
}

func (s *Server) evaluateIntegrations(ctx context.Context) {
	s.integrationMu.Lock()
	if s.integrationRunning {
		s.integrationMu.Unlock()
		return
	}
	s.integrationRunning = true
	s.integrationMu.Unlock()
	defer func() {
		s.integrationMu.Lock()
		s.integrationRunning = false
		s.integrationMu.Unlock()
	}()
	for _, source := range integrationOrder {
		cfg, err := s.loadIntegrationConfig(source)
		if err != nil {
			s.markIntegrationResult(source, err, "")
			continue
		}
		if !cfg.Enabled {
			continue
		}
		s.integrationMu.Lock()
		runtime := s.integrationRuntime[source]
		last, _ := time.Parse(time.RFC3339, runtime.lastPolledAt)
		due := last.IsZero() || time.Since(last) >= time.Duration(cfg.PollSeconds)*time.Second
		s.integrationMu.Unlock()
		if !due {
			continue
		}
		s.pollIntegration(ctx, cfg)
	}
}

func (s *Server) pollIntegration(ctx context.Context, cfg integrationConfig) {
	s.markIntegrationAttempt(cfg.Source, time.Now().UTC())
	pollCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	result, err := s.runIntegrationPoll(pollCtx, cfg)
	s.markIntegrationResult(cfg.Source, err, result.Summary)
	if err != nil {
		slog.Warn("integration poll failed", "source", cfg.Source, "error", err)
		return
	}
	s.processIntegrationFindings(cfg, result.Findings, time.Now().UTC())
}

func (s *Server) runIntegrationPoll(ctx context.Context, cfg integrationConfig) (integrationPollResult, error) {
	switch cfg.Source {
	case integrationHAProxy:
		return s.pollHAProxy(ctx, cfg)
	case integrationOPN:
		return s.pollOPNsense(ctx, cfg)
	case integrationVCenter:
		return s.pollVCenter(ctx, cfg)
	default:
		return integrationPollResult{}, errors.New("unknown integration")
	}
}

func (s *Server) processIntegrationFindings(cfg integrationConfig, findings []integrationFinding, now time.Time) {
	existing, err := s.store.ListIntegrationStates(cfg.Source)
	if err != nil {
		slog.Warn("integration state read failed", "source", cfg.Source, "error", err)
		return
	}
	current := make(map[string]integrationFinding, len(findings))
	for _, finding := range findings {
		current[finding.Key] = finding
	}
	label := integrationSources[cfg.Source].label
	for _, previous := range existing {
		finding, ok := current[previous.EventKey]
		if !ok {
			s.recordIntegrationEvent(cfg, label, previous.EventKey, "ok", previous.Subject,
				"recovered or no longer reported by "+label, cfg.Recipients, now)
			if err := s.store.DeleteIntegrationState(cfg.Source, previous.EventKey); err != nil {
				slog.Warn("integration state delete failed", "source", cfg.Source, "error", err)
			}
			continue
		}
		nowText := now.Format(time.RFC3339)
		if previous.Status != finding.Status || previous.Subject != finding.Subject {
			s.recordIntegrationEvent(cfg, label, finding.Key, finding.Status, finding.Subject, finding.Detail, cfg.Recipients, now)
			if err := s.store.UpsertIntegrationState(integrationStateFromFinding(cfg.Source, finding, previous.FirstSeen, nowText, nowText)); err != nil {
				slog.Warn("integration state update failed", "source", cfg.Source, "error", err)
			}
			delete(current, previous.EventKey)
			continue
		}
		if err := s.store.UpsertIntegrationState(integrationStateFromFinding(cfg.Source, finding, previous.FirstSeen, nowText, previous.LastNotified)); err != nil {
			slog.Warn("integration state update failed", "source", cfg.Source, "error", err)
		}
		delete(current, previous.EventKey)
	}
	for key, finding := range current {
		s.recordIntegrationEvent(cfg, label, key, finding.Status, finding.Subject, finding.Detail, cfg.Recipients, now)
		nowText := now.Format(time.RFC3339)
		if err := s.store.UpsertIntegrationState(integrationStateFromFinding(cfg.Source, finding, nowText, nowText, nowText)); err != nil {
			slog.Warn("integration state insert failed", "source", cfg.Source, "error", err)
		}
	}
}

func integrationStateFromFinding(source string, finding integrationFinding, firstSeen, lastSeen, lastNotified string) store.IntegrationState {
	return store.IntegrationState{
		Source: source, EventKey: finding.Key, Status: finding.Status, Subject: finding.Subject,
		Detail: finding.Detail, FirstSeen: firstSeen, LastSeen: lastSeen, LastNotified: lastNotified,
	}
}

func (s *Server) recordIntegrationEvent(cfg integrationConfig, label, key, status, subject, detail, recipients string, now time.Time) {
	severity := strings.ToUpper(status)
	if status == "ok" {
		severity = "RECOVERED"
	}
	emailSubject := fmt.Sprintf("[HIBP][%s] %s - %s", severity, label, subject)
	emailBody := fmt.Sprintf("HIBP integration alert\n\nSource: %s\nEvent: %s\nStatus: %s\nDetail: %s\nTime: %s\n",
		label, subject, status, detail, now.Format(time.RFC3339))
	emailed, emailError := s.sendIntegrationEmail(recipients, emailSubject, emailBody)
	if err := s.store.AddIntegrationEvent(store.IntegrationEvent{
		Source: cfg.Source, EventKey: key, Status: status, Subject: subject, Detail: detail,
		CreatedAt: now.Format(time.RFC3339), Emailed: emailed, Error: emailError,
	}); err != nil {
		slog.Warn("integration event save failed", "source", cfg.Source, "error", err)
	}
	_ = s.store.AddAudit("integration", "alert", cfg.Source, key, subject)
	if emailError != "" {
		slog.Warn("integration email not sent", "source", cfg.Source, "error", emailError)
	}
}

func (s *Server) sendIntegrationEmail(recipients, subject, body string) (bool, string) {
	cfg, err := s.loadSMTPConfig()
	if err != nil {
		return false, err.Error()
	}
	list := cfg.Recipients
	if strings.TrimSpace(recipients) != "" {
		list, err = mailer.ParseRecipients(recipients)
		if err != nil {
			return false, err.Error()
		}
	}
	if !cfg.Enabled {
		return false, "SMTP notifications are disabled"
	}
	if len(list) == 0 {
		return false, "no email recipients configured"
	}
	if err := s.sendEmail(cfg, list, subject, body); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func (s *Server) handleListIntegrations(w http.ResponseWriter, r *http.Request) {
	views := make([]integrationView, 0, len(integrationSources))
	for _, source := range integrationOrder {
		view, err := s.integrationView(source)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		views = append(views, view)
	}
	events, err := s.store.ListIntegrationEvents(200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []store.IntegrationEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": views, "events": events})
}

func (s *Server) handleGetIntegration(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if _, ok := integrationMetaFor(source); !ok {
		writeError(w, http.StatusNotFound, "unknown integration")
		return
	}
	view, err := s.integrationView(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"integration": view})
}

func (s *Server) handlePutIntegration(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if _, ok := integrationMetaFor(source); !ok {
		writeError(w, http.StatusNotFound, "unknown integration")
		return
	}
	var request integrationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	cfg, err := s.saveIntegrationConfig(source, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "integration-settings", "integration", source, "updated")
	view, _ := s.integrationView(source)
	if cfg.Enabled {
		select {
		case s.integrationWake <- struct{}{}:
		default:
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "integration": view})
}

func (s *Server) handleTestIntegration(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if _, ok := integrationMetaFor(source); !ok {
		writeError(w, http.StatusNotFound, "unknown integration")
		return
	}
	cfg, err := s.loadIntegrationConfig(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg.Enabled = true
	if err := validateIntegrationConfig(cfg, true); err != nil {
		writeError(w, http.StatusBadRequest, "integration is not configured: "+err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	result, err := s.runIntegrationPoll(ctx, cfg)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.markIntegrationResult(source, nil, result.Summary)
	_ = s.store.AddAudit(s.auditActor(r), "integration-test", "integration", source, "ok")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "summary": result.Summary})
}

func (s *Server) handleCheckIntegration(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if _, ok := integrationMetaFor(source); !ok {
		writeError(w, http.StatusNotFound, "unknown integration")
		return
	}
	cfg, err := s.loadIntegrationConfig(source)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "integration is disabled")
		return
	}
	s.integrationMu.Lock()
	runtime := s.integrationRuntime[source]
	runtime.lastPolledAt = ""
	s.integrationRuntime[source] = runtime
	s.integrationMu.Unlock()
	select {
	case s.integrationWake <- struct{}{}:
	default:
	}
	_ = s.store.AddAudit(s.auditActor(r), "integration-check", "integration", source, "queued")
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

// pollHAProxy reads the CSV stats endpoint. It never uses the HAProxy admin
// socket and never changes server state.
func (s *Server) pollHAProxy(ctx context.Context, cfg integrationConfig) (integrationPollResult, error) {
	client := s.integrationHTTPClient(cfg.Insecure)
	body, err := fetchHAProxyStats(ctx, client, cfg.URL, cfg.Username, cfg.Password)
	if err != nil {
		return integrationPollResult{}, err
	}
	return parseHAProxyStats(body)
}

func fetchHAProxyStats(ctx context.Context, client *http.Client, rawURL, username, password string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	candidates := []string{rawURL}
	if !strings.Contains(parsed.Path, ";csv") {
		csvURL := *parsed
		csvURL.Path = strings.TrimSuffix(csvURL.Path, "/") + ";csv"
		candidates = append(candidates, csvURL.String())
	}
	var lastErr error
	for _, candidate := range candidates {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "text/csv,text/plain;q=0.9,*/*;q=0.1")
		if username != "" {
			request.SetBasicAuth(username, password)
		}
		response, err := client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		_ = response.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			lastErr = fmt.Errorf("HAProxy stats returned HTTP %d", response.StatusCode)
			continue
		}
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 {
			lastErr = errors.New("HAProxy stats endpoint returned an empty response")
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("<")) || bytes.HasPrefix(trimmed, []byte("{")) {
			lastErr = errors.New("HAProxy stats endpoint did not return CSV; check the stats URI and add ;csv if needed")
			continue
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = errors.New("HAProxy stats endpoint did not return CSV")
	}
	return nil, lastErr
}

func parseHAProxyStats(body []byte) (integrationPollResult, error) {
	text := strings.TrimSpace(string(body))
	text = strings.TrimPrefix(text, "# ")
	reader := csv.NewReader(strings.NewReader(text))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return integrationPollResult{}, fmt.Errorf("parse HAProxy CSV: %w", err)
	}
	if len(records) < 2 {
		return integrationPollResult{}, errors.New("HAProxy stats CSV is empty")
	}
	header := make(map[string]int)
	for index, cell := range records[0] {
		header[strings.ToLower(strings.TrimSpace(cell))] = index
	}
	for _, required := range []string{"pxname", "svname", "status"} {
		if _, ok := header[required]; !ok {
			return integrationPollResult{}, fmt.Errorf("HAProxy stats CSV is missing %s", required)
		}
	}
	value := func(record []string, key string) string {
		index, ok := header[key]
		if !ok || index >= len(record) {
			return ""
		}
		return strings.TrimSpace(record[index])
	}
	backends := 0
	servers := 0
	var findings []integrationFinding
	for _, record := range records[1:] {
		if len(record) == 0 {
			continue
		}
		pxname := value(record, "pxname")
		svname := value(record, "svname")
		status := value(record, "status")
		if pxname == "" || svname == "" {
			continue
		}
		switch svname {
		case "FRONTEND":
			continue
		case "BACKEND":
			backends++
		default:
			servers++
		}
		upper := strings.ToUpper(status)
		if upper == "MAINT" || strings.HasPrefix(upper, "MAINT ") || upper == "DRAIN" || upper == "NO CHECK" || upper == "" {
			continue
		}
		severity := ""
		if upper == "DOWN" || upper == "NOLB" || upper == "SOCKERR" || upper == "INI" || strings.Contains(upper, "DOWN") {
			severity = "critical"
		} else if upper != "UP" {
			severity = "warning"
		}
		if severity == "" {
			continue
		}
		kind := "server"
		if svname == "BACKEND" {
			kind = "backend"
		}
		action := "down"
		if severity == "warning" {
			action = "degraded"
		}
		detail := fmt.Sprintf("status=%s, check=%s %s, address=%s, last change=%s",
			status, value(record, "check_status"), value(record, "check_code"), value(record, "addr"), value(record, "lastchg"))
		findings = append(findings, integrationFinding{
			Key: pxname + "/" + svname, Status: severity,
			Subject: fmt.Sprintf("HAProxy %s %s - %s/%s", kind, action, pxname, svname),
			Detail:  detail,
		})
	}
	return integrationPollResult{
		Summary:  fmt.Sprintf("%d backends, %d servers, %d down/degraded", backends, servers, len(findings)),
		Findings: findings,
	}, nil
}

func (s *Server) pollOPNsense(ctx context.Context, cfg integrationConfig) (integrationPollResult, error) {
	base := strings.TrimRight(cfg.URL, "/")
	endpoint := base + "/api/routes/gateway/status"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return integrationPollResult{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(cfg.APIKey, cfg.APISecret)
	client := s.integrationHTTPClient(cfg.Insecure)
	response, err := client.Do(request)
	if err != nil {
		return integrationPollResult{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return integrationPollResult{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return integrationPollResult{}, fmt.Errorf("OPNsense API returned HTTP %d", response.StatusCode)
	}
	var gateways []struct {
		Name    string          `json:"name"`
		Address string          `json:"address"`
		Status  string          `json:"status"`
		Delay   json.RawMessage `json:"delay"`
		StdDev  json.RawMessage `json:"stddev"`
		Loss    json.RawMessage `json:"loss"`
	}
	if err := json.Unmarshal(body, &gateways); err != nil {
		var wrapper struct {
			Data []json.RawMessage `json:"data"`
		}
		if wrapperErr := json.Unmarshal(body, &wrapper); wrapperErr != nil || len(wrapper.Data) == 0 {
			return integrationPollResult{}, fmt.Errorf("parse OPNsense gateway status: %w", err)
		}
		encoded, _ := json.Marshal(wrapper.Data)
		if err := json.Unmarshal(encoded, &gateways); err != nil {
			return integrationPollResult{}, fmt.Errorf("parse OPNsense gateway status: %w", err)
		}
	}
	var findings []integrationFinding
	for _, gateway := range gateways {
		name := strings.TrimSpace(gateway.Name)
		if name == "" {
			name = strings.TrimSpace(gateway.Address)
		}
		status := strings.ToLower(strings.TrimSpace(gateway.Status))
		severity := ""
		switch status {
		case "none", "online", "up":
			continue
		case "down":
			severity = "critical"
		case "loss":
			severity = "warning"
		default:
			severity = "warning"
		}
		detail := fmt.Sprintf("status=%s, delay=%s, loss=%s, stddev=%s",
			gateway.Status, jsonScalarText(gateway.Delay), jsonScalarText(gateway.Loss), jsonScalarText(gateway.StdDev))
		findings = append(findings, integrationFinding{
			Key: name, Status: severity, Subject: fmt.Sprintf("OPNsense gateway %s - %s", map[string]string{"critical": "down", "warning": "degraded"}[severity], name),
			Detail: detail,
		})
	}
	return integrationPollResult{
		Summary:  fmt.Sprintf("%d gateways, %d down/degraded", len(gateways), len(findings)),
		Findings: findings,
	}, nil
}

func jsonScalarText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return strings.Trim(string(raw), `"`)
}
