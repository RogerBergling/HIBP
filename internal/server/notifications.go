package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/mailer"
)

const smtpScope = "smtp"

type smtpView struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Mode           string `json:"mode"`
	Username       string `json:"username"`
	From           string `json:"from"`
	Recipients     string `json:"recipients"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	PasswordSet    bool   `json:"password_set"`
}

type smtpRequest struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Mode           string `json:"mode"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	ClearPassword  bool   `json:"clear_password"`
	From           string `json:"from"`
	Recipients     string `json:"recipients"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func (s *Server) loadSMTPConfig() (mailer.Config, error) {
	settings, err := s.store.ListSettings(smtpScope)
	if err != nil {
		return mailer.Config{}, err
	}
	port := 587
	if value, err := strconv.Atoi(settings["port"]); err == nil && value > 0 {
		port = value
	}
	timeout := 15
	if value, err := strconv.Atoi(settings["timeout_seconds"]); err == nil && value > 0 {
		timeout = value
	}
	mode := strings.TrimSpace(settings["mode"])
	if mode == "" {
		mode = mailer.ModeStartTLS
	}
	var recipients []string
	if value := strings.TrimSpace(settings["recipients"]); value != "" {
		recipients, err = mailer.ParseRecipients(value)
		if err != nil {
			return mailer.Config{}, err
		}
	}
	cfg := mailer.Config{
		Enabled:    settings["enabled"] == "1",
		Host:       strings.TrimSpace(settings["host"]),
		Port:       port,
		Mode:       mode,
		Username:   settings["username"],
		Password:   settings["password"],
		From:       strings.TrimSpace(settings["from"]),
		Recipients: recipients,
		Timeout:    time.Duration(timeout) * time.Second,
	}
	return cfg, nil
}

func smtpViewFromConfig(cfg mailer.Config) smtpView {
	return smtpView{
		Enabled: cfg.Enabled, Host: cfg.Host, Port: cfg.Port, Mode: cfg.Mode,
		Username: cfg.Username, From: cfg.From,
		Recipients:     strings.Join(cfg.Recipients, ", "),
		TimeoutSeconds: int(cfg.Timeout / time.Second), PasswordSet: cfg.Password != "",
	}
}

func (s *Server) handleGetSMTP(w http.ResponseWriter, _ *http.Request) {
	cfg, err := s.loadSMTPConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"smtp": smtpViewFromConfig(cfg)})
}

func (s *Server) handlePutSMTP(w http.ResponseWriter, r *http.Request) {
	var request smtpRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	existing, err := s.loadSMTPConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	password := existing.Password
	if request.Password != "" {
		password = request.Password
	}
	if request.ClearPassword || request.Username == "" {
		password = ""
	}
	recipients, err := parseRecipientsOptional(request.Recipients)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := strings.TrimSpace(request.Mode)
	if mode == "" {
		mode = mailer.ModeStartTLS
	}
	timeout := request.TimeoutSeconds
	if timeout <= 0 {
		timeout = 15
	}
	cfg := mailer.Config{
		Enabled: request.Enabled, Host: strings.TrimSpace(request.Host), Port: request.Port,
		Mode: mode, Username: strings.TrimSpace(request.Username), Password: password,
		From: strings.TrimSpace(request.From), Recipients: recipients,
		Timeout: time.Duration(timeout) * time.Second,
	}
	if request.Enabled || cfg.Host != "" || cfg.From != "" || len(cfg.Recipients) > 0 {
		if err := cfg.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	values := map[string]string{
		"enabled":         boolString(cfg.Enabled),
		"host":            cfg.Host,
		"port":            strconv.Itoa(cfg.Port),
		"mode":            cfg.Mode,
		"username":        cfg.Username,
		"from":            cfg.From,
		"recipients":      strings.Join(cfg.Recipients, ", "),
		"timeout_seconds": strconv.Itoa(timeout),
	}
	if cfg.Password != "" {
		values["password"] = cfg.Password
	}
	for key, value := range values {
		if err := s.store.SetSetting(smtpScope, key, value); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if cfg.Password == "" {
		_ = s.store.DeleteSetting(smtpScope, "password")
	}
	_ = s.store.AddAudit(s.auditActor(r), "smtp-settings", "notifications", smtpScope, "updated")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "smtp": smtpViewFromConfig(cfg)})
}

type smtpTestRequest struct {
	To string `json:"to"`
}

func (s *Server) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	var request smtpTestRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	cfg, err := s.loadSMTPConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "SMTP is not configured: "+err.Error())
		return
	}
	// A test message must work before alerts are enabled.
	cfg.Enabled = true
	to := cfg.Recipients
	if strings.TrimSpace(request.To) != "" {
		to, err = parseRecipientsOptional(request.To)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.sendEmail(cfg, to, "HIBP SMTP test", "This is a test email from HIBP. SMTP delivery is working.\n"); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "smtp-test", "notifications", smtpScope, "test email sent")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recipients": to})
}

func (s *Server) sendEmail(cfg mailer.Config, to []string, subject, body string) error {
	if !cfg.Enabled {
		return errors.New("SMTP notifications are disabled")
	}
	s.mailMu.Lock()
	defer s.mailMu.Unlock()
	return mailer.Send(cfg, to, subject, body)
}

func parseRecipientsOptional(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	return mailer.ParseRecipients(value)
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
