package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/store"
)

var monitorTypes = map[string]bool{
	"host.cpu": true, "host.memory": true, "host.disk": true, "host.load": true,
	"docker.project": true, "docker.container": true, "service.systemd": true,
	"http": true, "tcp": true, "ssl": true,
}

var monitorContainerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var monitorServicePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,127}$`)

type monitorRequest struct {
	Name            string                    `json:"name"`
	Type            string                    `json:"type"`
	Target          string                    `json:"target"`
	Warning         float64                   `json:"warning"`
	Critical        float64                   `json:"critical"`
	IntervalSeconds int                       `json:"interval_seconds"`
	RepeatMinutes   int                       `json:"repeat_minutes"`
	CooldownMinutes int                       `json:"cooldown_minutes"`
	Recipients      string                    `json:"recipients"`
	Enabled         bool                      `json:"enabled"`
	Assignments     []store.MonitorAssignment `json:"assignments"`
}

func (s *Server) validateMonitor(request monitorRequest, monitorID string) (store.Monitor, error) {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		return store.Monitor{}, errors.New("monitor name is required")
	}
	if !monitorTypes[request.Type] {
		return store.Monitor{}, errors.New("unsupported monitor type")
	}
	target := strings.TrimSpace(request.Target)
	switch request.Type {
	case "host.cpu", "host.memory", "host.load":
		if target != "" {
			return store.Monitor{}, errors.New("this monitor type does not take a target")
		}
	case "host.disk":
		if target == "" {
			target = "/"
		}
		if !strings.HasPrefix(target, "/") {
			return store.Monitor{}, errors.New("disk monitor target must be an absolute mount path")
		}
	case "docker.project":
		if !dockerProjectPattern.MatchString(target) {
			return store.Monitor{}, errors.New("docker.project requires a valid Compose project name")
		}
	case "docker.container":
		if !monitorContainerPattern.MatchString(target) {
			return store.Monitor{}, errors.New("docker.container requires a valid container name")
		}
	case "service.systemd":
		if !monitorServicePattern.MatchString(target) {
			return store.Monitor{}, errors.New("service.systemd requires a valid unit name")
		}
	case "http":
		parsed, err := url.Parse(target)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return store.Monitor{}, errors.New("HTTP monitor target must be an http:// or https:// URL")
		}
		if parsed.User != nil {
			return store.Monitor{}, errors.New("HTTP monitor targets must not contain credentials")
		}
	case "tcp", "ssl":
		host, port, err := net.SplitHostPort(target)
		if err != nil || host == "" {
			return store.Monitor{}, errors.New("target must be host:port")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return store.Monitor{}, errors.New("target port must be between 1 and 65535")
		}
	}
	switch request.Type {
	case "host.cpu", "host.memory", "host.disk":
		if request.Warning < 0 || request.Critical > 100 || request.Warning <= 0 || request.Critical <= request.Warning {
			return store.Monitor{}, errors.New("percentage thresholds require 0 < warning < critical <= 100")
		}
	case "host.load":
		if request.Warning <= 0 || request.Critical <= request.Warning {
			return store.Monitor{}, errors.New("load thresholds require 0 < warning < critical")
		}
	case "ssl":
		if request.Warning <= 0 || request.Critical <= 0 || request.Critical >= request.Warning {
			return store.Monitor{}, errors.New("SSL thresholds require 0 < critical < warning days")
		}
	case "http", "tcp":
		if request.Warning < 0 || request.Critical < 0 || (request.Critical > 0 && request.Warning > request.Critical) {
			return store.Monitor{}, errors.New("latency thresholds must be 0 or 0 <= warning <= critical")
		}
	default:
		request.Warning = 0
		request.Critical = 0
	}
	if request.IntervalSeconds < 30 || request.IntervalSeconds > 86400 {
		return store.Monitor{}, errors.New("interval_seconds must be between 30 and 86400")
	}
	if request.RepeatMinutes < 0 || request.RepeatMinutes > 10080 {
		return store.Monitor{}, errors.New("repeat_minutes must be between 0 and 10080")
	}
	if request.CooldownMinutes < 0 || request.CooldownMinutes > 1440 {
		return store.Monitor{}, errors.New("cooldown_minutes must be between 0 and 1440")
	}
	var recipients []string
	if strings.TrimSpace(request.Recipients) != "" {
		parsed, err := mailer.ParseRecipients(request.Recipients)
		if err != nil {
			return store.Monitor{}, err
		}
		recipients = parsed
	}
	if len(request.Assignments) == 0 {
		return store.Monitor{}, errors.New("at least one monitor assignment is required")
	}
	assignments := make([]store.MonitorAssignment, 0, len(request.Assignments))
	seen := make(map[string]bool)
	for _, assignment := range request.Assignments {
		scope := strings.TrimSpace(assignment.Scope)
		assignmentTarget := strings.TrimSpace(assignment.Target)
		switch scope {
		case "fleet":
			assignmentTarget = ""
		case "host":
			if assignmentTarget == "" {
				return store.Monitor{}, errors.New("host assignment requires a host id")
			}
			if _, err := s.store.GetHost(assignmentTarget); err != nil {
				return store.Monitor{}, errors.New("host assignment references an unknown host")
			}
		case "group", "tag":
			if assignmentTarget == "" {
				return store.Monitor{}, errors.New("group/tag assignment requires a value")
			}
		default:
			return store.Monitor{}, errors.New("assignment scope must be fleet, host, group, or tag")
		}
		key := scope + "\x00" + assignmentTarget
		if seen[key] {
			continue
		}
		seen[key] = true
		assignments = append(assignments, store.MonitorAssignment{MonitorID: monitorID, Scope: scope, Target: assignmentTarget})
	}
	return store.Monitor{
		ID: monitorID, Name: name, Type: request.Type, Target: target,
		Warning: request.Warning, Critical: request.Critical,
		IntervalSeconds: request.IntervalSeconds, RepeatMinutes: request.RepeatMinutes,
		CooldownMinutes: request.CooldownMinutes, Recipients: strings.Join(recipients, ", "),
		Enabled: request.Enabled, Assignments: assignments,
	}, nil
}

func (s *Server) handleListMonitors(w http.ResponseWriter, _ *http.Request) {
	monitors, err := s.store.ListMonitors()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for index := range monitors {
		monitors[index].Assignments, _ = s.store.ListMonitorAssignments(monitors[index].ID)
		monitors[index].States, _ = s.store.ListMonitorStates(monitors[index].ID)
	}
	if monitors == nil {
		monitors = []store.Monitor{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"monitors": monitors})
}

func (s *Server) handleCreateMonitor(w http.ResponseWriter, r *http.Request) {
	var request monitorRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	monitor, err := s.validateMonitor(request, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	monitor, err = s.store.CreateMonitor(monitor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "monitor-create", "monitor", monitor.ID, monitor.Name)
	monitor.Assignments, _ = s.store.ListMonitorAssignments(monitor.ID)
	writeJSON(w, http.StatusCreated, monitor)
}

func (s *Server) handleUpdateMonitor(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetMonitor(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	var request monitorRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	monitor, err := s.validateMonitor(request, existing.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	monitor.CreatedAt = existing.CreatedAt
	monitor.LastCheckedAt = existing.LastCheckedAt
	if err := s.store.UpdateMonitor(monitor); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "monitor-update", "monitor", monitor.ID, monitor.Name)
	monitor.Assignments, _ = s.store.ListMonitorAssignments(monitor.ID)
	monitor.States, _ = s.store.ListMonitorStates(monitor.ID)
	writeJSON(w, http.StatusOK, monitor)
}

func (s *Server) handleDeleteMonitor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	monitor, err := s.store.GetMonitor(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	if err := s.store.DeleteMonitor(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "monitor-delete", "monitor", id, monitor.Name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleCheckMonitor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	monitor, err := s.store.GetMonitor(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "monitor not found")
		return
	}
	if !monitor.Enabled {
		writeError(w, http.StatusBadRequest, "monitor is disabled")
		return
	}
	// Make the next engine pass treat this monitor as due, then wake the engine.
	if err := s.store.SetMonitorChecked(id, "1970-01-01T00:00:00Z"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	select {
	case s.monitorWake <- struct{}{}:
	default:
	}
	_ = s.store.AddAudit(s.auditActor(r), "monitor-check", "monitor", id, monitor.Name)
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	events, err := s.store.ListAlertEvents(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []store.AlertEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": events})
}
