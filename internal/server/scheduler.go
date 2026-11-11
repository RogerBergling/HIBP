package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/robfig/cron/v3"
)

type scheduleRequest struct {
	Name           string                     `json:"name"`
	Mode           string                     `json:"mode"`
	Enabled        bool                       `json:"enabled"`
	Cron           string                     `json:"cron"`
	Timezone       string                     `json:"timezone"`
	WindowMinutes  int                        `json:"window_minutes"`
	JitterSeconds  int                        `json:"jitter_seconds"`
	MaxConcurrency int                        `json:"max_concurrency"`
	RunIfMissed    bool                       `json:"run_if_missed"`
	Notify         string                     `json:"notify"`
	Recipients     string                     `json:"recipients"`
	Assignments    []store.ScheduleAssignment `json:"assignments"`
}

func (s *Server) validateScheduleRequest(scheduleID string, request scheduleRequest) (store.Schedule, error) {
	name := strings.TrimSpace(request.Name)
	if name == "" {
		return store.Schedule{}, errors.New("schedule name is required")
	}
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	if mode != "check" && mode != "apply" {
		return store.Schedule{}, errors.New("mode must be check or apply")
	}
	cronSpec := strings.TrimSpace(request.Cron)
	if cronSpec == "" || len(cronSpec) > 256 {
		return store.Schedule{}, errors.New("cron expression is required and must be at most 256 characters")
	}
	if _, err := cron.ParseStandard(cronSpec); err != nil {
		return store.Schedule{}, fmt.Errorf("invalid cron expression: %w", err)
	}
	timezone := strings.TrimSpace(request.Timezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return store.Schedule{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	window := request.WindowMinutes
	if window <= 0 {
		window = 120
	}
	if window < 5 || window > 1440 {
		return store.Schedule{}, errors.New("window_minutes must be between 5 and 1440")
	}
	if request.JitterSeconds < 0 || request.JitterSeconds > 3600 {
		return store.Schedule{}, errors.New("jitter_seconds must be between 0 and 3600")
	}
	concurrency := request.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency < 1 || concurrency > 20 {
		return store.Schedule{}, errors.New("max_concurrency must be between 1 and 20")
	}
	notify := strings.ToLower(strings.TrimSpace(request.Notify))
	if notify == "" {
		notify = "failures"
	}
	if notify != "never" && notify != "failures" && notify != "always" {
		return store.Schedule{}, errors.New("notify must be never, failures, or always")
	}
	var recipients []string
	if strings.TrimSpace(request.Recipients) != "" {
		parsed, err := mailer.ParseRecipients(request.Recipients)
		if err != nil {
			return store.Schedule{}, err
		}
		recipients = parsed
	}
	if len(request.Assignments) == 0 {
		return store.Schedule{}, errors.New("at least one assignment is required")
	}
	assignments := make([]store.ScheduleAssignment, 0, len(request.Assignments))
	seen := make(map[string]bool)
	for _, assignment := range request.Assignments {
		scope := strings.TrimSpace(assignment.Scope)
		target := strings.TrimSpace(assignment.Target)
		switch scope {
		case "fleet":
			target = ""
		case "host":
			if target == "" {
				return store.Schedule{}, errors.New("host assignment requires a host id")
			}
			if _, err := s.store.GetHost(target); err != nil {
				return store.Schedule{}, errors.New("host assignment references an unknown host")
			}
		case "group", "tag":
			if target == "" {
				return store.Schedule{}, errors.New("group/tag assignment requires a value")
			}
		default:
			return store.Schedule{}, errors.New("assignment scope must be fleet, host, group, or tag")
		}
		key := scope + "\x00" + target
		if seen[key] {
			continue
		}
		seen[key] = true
		assignments = append(assignments, store.ScheduleAssignment{ScheduleID: scheduleID, Scope: scope, Target: target})
	}
	return store.Schedule{
		ID: scheduleID, Name: name, Mode: mode, Enabled: request.Enabled, Cron: cronSpec,
		Timezone: timezone, WindowMinutes: window, JitterSeconds: request.JitterSeconds,
		MaxConcurrency: concurrency, RunIfMissed: request.RunIfMissed, Notify: notify,
		Recipients: strings.Join(recipients, ", "), Assignments: assignments,
	}, nil
}

func scheduleTiming(schedule store.Schedule) (cron.Schedule, *time.Location, error) {
	timezone := strings.TrimSpace(schedule.Timezone)
	if timezone == "" {
		timezone = "UTC"
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, nil, err
	}
	spec, err := cron.ParseStandard(strings.TrimSpace(schedule.Cron))
	if err != nil {
		return nil, nil, err
	}
	return spec, location, nil
}

func nextScheduleRun(schedule store.Schedule, now time.Time) string {
	spec, location, err := scheduleTiming(schedule)
	if err != nil {
		return ""
	}
	next := spec.Next(now.In(location))
	if next.IsZero() {
		return ""
	}
	return next.UTC().Format(time.RFC3339)
}

// dueScheduleOccurrence returns the most recent due occurrence, whether it
// should run now, and the most recent occurrence skipped because it was outside
// the maintenance window.
func dueScheduleOccurrence(schedule store.Schedule, now time.Time) (time.Time, bool, time.Time) {
	spec, location, err := scheduleTiming(schedule)
	if err != nil {
		return time.Time{}, false, time.Time{}
	}
	baseText := schedule.LastRunAt
	if strings.TrimSpace(baseText) == "" {
		baseText = schedule.CreatedAt
	}
	base, err := time.Parse(time.RFC3339Nano, baseText)
	if err != nil || base.IsZero() {
		base = now.Add(-time.Duration(schedule.WindowMinutes+1) * time.Minute)
	}
	localNow := now.In(location)
	next := spec.Next(base.In(location))
	var candidate time.Time
	var skipped time.Time
	for !next.IsZero() && !next.After(localNow) {
		if localNow.Sub(next) <= time.Duration(schedule.WindowMinutes)*time.Minute || schedule.RunIfMissed {
			candidate = next
		}
		skipped = next
		next = spec.Next(next)
	}
	if !candidate.IsZero() {
		return candidate, true, time.Time{}
	}
	return time.Time{}, false, skipped
}

func (s *Server) RunScheduler(ctx context.Context) {
	s.schedulerMu.Lock()
	s.schedulerCtx = ctx
	s.schedulerMu.Unlock()
	defer func() {
		s.schedulerMu.Lock()
		s.schedulerCtx = nil
		s.schedulerMu.Unlock()
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluateSchedules()
		case <-s.schedulerWake:
			s.evaluateSchedules()
		}
	}
}

func (s *Server) evaluateSchedules() {
	s.schedulerMu.Lock()
	if s.schedulerScanning {
		s.schedulerMu.Unlock()
		return
	}
	s.schedulerScanning = true
	s.schedulerMu.Unlock()
	defer func() {
		s.schedulerMu.Lock()
		s.schedulerScanning = false
		s.schedulerMu.Unlock()
	}()
	schedules, err := s.store.ListSchedules()
	if err != nil {
		slog.Warn("scheduler: list schedules", "error", err)
		return
	}
	now := time.Now().UTC()
	for _, schedule := range schedules {
		if !schedule.Enabled {
			continue
		}
		occurrence, due, skipped := dueScheduleOccurrence(schedule, now)
		if !due {
			if !skipped.IsZero() {
				_ = s.store.SetScheduleLastRunAt(schedule.ID, skipped.UTC().Format(time.RFC3339Nano))
			}
			continue
		}
		if !s.launchSchedule(schedule, occurrence, false) {
			continue
		}
		_ = s.store.SetScheduleLastRunAt(schedule.ID, occurrence.UTC().Format(time.RFC3339Nano))
	}
}

func (s *Server) launchSchedule(schedule store.Schedule, occurrence time.Time, manual bool) bool {
	s.schedulerMu.Lock()
	if s.schedulerRunning[schedule.ID] {
		s.schedulerMu.Unlock()
		return false
	}
	ctx := s.schedulerCtx
	if ctx == nil {
		ctx = context.Background()
	}
	s.schedulerRunning[schedule.ID] = true
	s.schedulerMu.Unlock()
	go s.runSchedule(ctx, schedule, occurrence, manual)
	return true
}

func (s *Server) runSchedule(ctx context.Context, schedule store.Schedule, occurrence time.Time, manual bool) {
	defer func() {
		s.schedulerMu.Lock()
		delete(s.schedulerRunning, schedule.ID)
		s.schedulerMu.Unlock()
	}()
	started := time.Now().UTC()
	if !manual && schedule.JitterSeconds > 0 {
		timer := time.NewTimer(time.Duration(schedule.JitterSeconds) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			_ = s.store.SetScheduleResult(schedule.ID, "failed", "schedule canceled before start")
			return
		case <-timer.C:
		}
	}
	assignments, err := s.store.ListScheduleAssignments(schedule.ID)
	if err != nil {
		_ = s.store.SetScheduleResult(schedule.ID, "failed", err.Error())
		return
	}
	hosts, err := s.store.ListHosts()
	if err != nil {
		_ = s.store.SetScheduleResult(schedule.ID, "failed", err.Error())
		return
	}
	hostByID := make(map[string]store.Host, len(hosts))
	for _, host := range hosts {
		hostByID[host.ID] = host
	}
	monitorAssignments := make([]store.MonitorAssignment, 0, len(assignments))
	for _, assignment := range assignments {
		monitorAssignments = append(monitorAssignments, store.MonitorAssignment{
			Scope: assignment.Scope, Target: assignment.Target,
		})
	}
	targets, active, _ := resolveMonitorTargets("host.cpu", monitorAssignments, hostByID)
	if !active {
		summary := "no hosts matched the schedule assignment"
		_ = s.store.SetScheduleResult(schedule.ID, "skipped", summary)
		s.auditScheduledRun(schedule, "skipped", summary, started)
		return
	}
	var eligible []store.Host
	skipped := 0
	for _, host := range targets {
		if host.AuthType != "key" {
			skipped++
			continue
		}
		key, err := s.store.GetHostKey(host.ID)
		if err != nil || key == nil {
			skipped++
			continue
		}
		eligible = append(eligible, host)
	}
	if len(eligible) == 0 {
		summary := fmt.Sprintf("no eligible key-auth hosts (%d skipped)", skipped)
		_ = s.store.SetScheduleResult(schedule.ID, "skipped", summary)
		s.auditScheduledRun(schedule, "skipped", summary, started)
		return
	}
	action := "check"
	timeout := 10 * time.Minute
	if schedule.Mode == "apply" {
		action = "apply"
		timeout = 45 * time.Minute
	}
	maxConcurrency := schedule.MaxConcurrency
	if maxConcurrency < 1 {
		maxConcurrency = 3
	}
	if maxConcurrency > 20 {
		maxConcurrency = 20
	}
	semaphore := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0
	failed := 0
	var failures []string
	for _, host := range eligible {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			s.schedulerSlots <- struct{}{}
			defer func() { <-s.schedulerSlots }()
			if ctx.Err() != nil {
				mu.Lock()
				failed++
				failures = append(failures, host.Name+": canceled")
				mu.Unlock()
				return
			}
			runStarted := time.Now().UTC()
			run, startErr := s.store.StartRun(store.Run{
				ScheduleID: schedule.ID, HostID: host.ID, Action: "patch-" + action,
				StartedAt: runStarted.Format(time.RFC3339Nano), Status: "running",
			})
			if startErr != nil {
				slog.Warn("scheduler: start run", "host", host.Name, "error", startErr)
				mu.Lock()
				failed++
				failures = append(failures, host.Name+": "+startErr.Error())
				mu.Unlock()
				return
			}
			output, code, runErr := s.runHelper(ctx, host, action, "", "", timeout)
			success := false
			exitCode := code
			detail := output
			errorText := ""
			var result helper.Result
			if json.Unmarshal([]byte(output), &result) == nil {
				success = runErr == nil && result.OK
				exitCode = result.ExitCode
				detail = result.Output
				errorText = result.Error
			} else if runErr == nil {
				success = code == 0
			}
			if runErr != nil {
				success = false
				errorText = runErr.Error()
				if detail == "" {
					detail = runErr.Error()
				}
			}
			if detail == "" && errorText != "" {
				detail = errorText
			}
			status := "success"
			if !success {
				status = "failed"
			}
			_ = s.store.FinishRun(run.ID, status, exitCode, truncateRunOutput(detail), truncateRunOutput(errorText), time.Now().UTC().Format(time.RFC3339Nano))
			_ = s.store.AddAudit("scheduler", "scheduled-patch", "host", host.ID,
				fmt.Sprintf("schedule=%s action=%s status=%s exit=%d", schedule.Name, action, status, exitCode))
			mu.Lock()
			if success {
				succeeded++
			} else {
				failed++
				if len(failures) < 20 {
					failures = append(failures, host.Name+": "+shortRunSummary(detail))
				}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	finished := time.Now().UTC()
	status := "success"
	if failed > 0 {
		status = "failed"
	}
	summary := fmt.Sprintf("%d succeeded, %d failed, %d skipped", succeeded, failed, skipped)
	_ = s.store.SetScheduleResult(schedule.ID, status, summary)
	s.auditScheduledRun(schedule, status, summary, started)
	if schedule.Notify == "always" || (schedule.Notify == "failures" && failed > 0) {
		body := fmt.Sprintf("HIBP scheduled patch run\n\nSchedule: %s\nMode: %s\nOccurrence: %s\nStarted: %s\nFinished: %s\nResult: %s\n\n%s\n",
			schedule.Name, schedule.Mode, occurrence.UTC().Format(time.RFC3339), started.Format(time.RFC3339),
			finished.Format(time.RFC3339), summary, strings.Join(failures, "\n"))
		if len(failures) == 0 {
			body += "No failures."
		}
		subject := fmt.Sprintf("[HIBP][SCHEDULE] %s - %s - %s", schedule.Name, schedule.Mode, summary)
		if _, emailError := s.sendIntegrationEmail(schedule.Recipients, subject, body); emailError != "" {
			slog.Warn("scheduler: email not sent", "schedule", schedule.Name, "error", emailError)
		}
	}
}

func (s *Server) auditScheduledRun(schedule store.Schedule, status, summary string, started time.Time) {
	_ = s.store.AddAudit("scheduler", "schedule-run", "schedule", schedule.ID,
		fmt.Sprintf("name=%s status=%s %s started=%s", schedule.Name, status, summary, started.Format(time.RFC3339)))
}

func truncateRunOutput(value string) string {
	const limit = 16 << 10
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n[output truncated]"
}

func shortRunSummary(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	const limit = 240
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

func (s *Server) handleListSchedules(w http.ResponseWriter, _ *http.Request) {
	schedules, err := s.store.ListSchedules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for index := range schedules {
		schedules[index].Assignments, _ = s.store.ListScheduleAssignments(schedules[index].ID)
		schedules[index].NextRunAt = nextScheduleRun(schedules[index], time.Now().UTC())
	}
	if schedules == nil {
		schedules = []store.Schedule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": schedules})
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var request scheduleRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	schedule, err := s.validateScheduleRequest("", request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	schedule, err = s.store.CreateSchedule(schedule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "schedule-create", "schedule", schedule.ID, schedule.Name)
	select {
	case s.schedulerWake <- struct{}{}:
	default:
	}
	schedules := []store.Schedule{schedule}
	schedules[0].NextRunAt = nextScheduleRun(schedule, time.Now().UTC())
	writeJSON(w, http.StatusCreated, schedules[0])
}

func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	var request scheduleRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	schedule, err := s.validateScheduleRequest(existing.ID, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	schedule.CreatedAt = existing.CreatedAt
	schedule.LastRunAt = existing.LastRunAt
	schedule.LastStatus = existing.LastStatus
	schedule.LastSummary = existing.LastSummary
	if err := s.store.UpdateSchedule(schedule); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "schedule-update", "schedule", schedule.ID, schedule.Name)
	select {
	case s.schedulerWake <- struct{}{}:
	default:
	}
	schedule.Assignments, _ = s.store.ListScheduleAssignments(schedule.ID)
	schedule.NextRunAt = nextScheduleRun(schedule, time.Now().UTC())
	writeJSON(w, http.StatusOK, schedule)
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	schedule, err := s.store.GetSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err := s.store.DeleteSchedule(schedule.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "schedule-delete", "schedule", schedule.ID, schedule.Name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleRunSchedule(w http.ResponseWriter, r *http.Request) {
	schedule, err := s.store.GetSchedule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	if !schedule.Enabled {
		writeError(w, http.StatusBadRequest, "schedule is disabled")
		return
	}
	if !s.launchSchedule(schedule, time.Now().UTC(), true) {
		writeError(w, http.StatusConflict, "schedule is already running")
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "schedule-run-now", "schedule", schedule.ID, schedule.Name)
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	runs, err := s.store.ListRuns(limit, r.URL.Query().Get("schedule_id"), r.URL.Query().Get("host_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if runs == nil {
		runs = []store.Run{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}
