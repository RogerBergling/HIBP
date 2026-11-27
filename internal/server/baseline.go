package server

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

type serviceBaselineUpdateRequest struct {
	Excluded bool `json:"excluded"`
}

type serviceBaselineView struct {
	HostID   string                  `json:"host_id"`
	Baseline []store.ServiceBaseline `json:"baseline"`
	Current  []store.ServiceState    `json:"current"`
	Enabled  bool                    `json:"enabled"`
	AutoAdd  bool                    `json:"auto_add"`
}

func (s *Server) serviceBaselineView(host store.Host) (serviceBaselineView, error) {
	baseline, err := s.store.ListServiceBaseline(host.ID)
	if err != nil {
		return serviceBaselineView{}, err
	}
	current, err := s.store.ListServiceStates(host.ID)
	if err != nil {
		return serviceBaselineView{}, err
	}
	if baseline == nil {
		baseline = []store.ServiceBaseline{}
	}
	if current == nil {
		current = []store.ServiceState{}
	}
	return serviceBaselineView{
		HostID: host.ID, Baseline: baseline, Current: current,
		Enabled: s.store.ResolveSetting(host.ID, "monitor.service_baseline.enabled", "1") != "0",
		AutoAdd: s.store.ResolveSetting(host.ID, "monitor.service_baseline.auto_add", "1") != "0",
	}, nil
}

func (s *Server) handleGetServiceBaseline(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	view, err := s.serviceBaselineView(host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleUpdateServiceBaseline(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	unit := strings.TrimSpace(r.PathValue("unit"))
	if !monitorServicePattern.MatchString(unit) {
		writeError(w, http.StatusBadRequest, "a valid systemd unit is required")
		return
	}
	var request serviceBaselineUpdateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := s.store.SetServiceBaselineExcluded(host.ID, unit, request.Excluded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "unit is not in the service baseline")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	action := "service-baseline-include"
	if request.Excluded {
		action = "service-baseline-exclude"
	}
	_ = s.store.AddAudit(s.auditActor(r), action, "host", host.ID, unit)
	s.markBaselineMonitorsDue()
	view, err := s.serviceBaselineView(host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleResetServiceBaseline(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	states, err := s.store.ListServiceStates(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	latest := time.Time{}
	var running []string
	for _, state := range states {
		if seen, err := time.Parse(time.RFC3339Nano, state.LastSeen); err == nil && seen.After(latest) {
			latest = seen
		}
		if state.State == "running" {
			running = append(running, state.Unit)
		}
	}
	if len(states) == 0 {
		writeError(w, http.StatusConflict, "no service state has been collected yet; collect metrics first")
		return
	}
	if latest.IsZero() || time.Since(latest) > s.metricsFreshness(host.ID) {
		writeError(w, http.StatusConflict, "service state is stale; collect fresh metrics before resetting the baseline")
		return
	}
	if len(running) == 0 {
		writeError(w, http.StatusConflict, "no running services were reported; the baseline was not changed")
		return
	}
	if err := s.store.ResetServiceBaseline(host.ID, running); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "service-baseline-reset", "host", host.ID,
		"baseline rebuilt from current running services; exclusions preserved")
	s.markBaselineMonitorsDue()
	view, err := s.serviceBaselineView(host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// markBaselineMonitorsDue makes the next monitoring pass re-evaluate every
// service-baseline monitor after an exclusion, reset, or per-host setting
// change instead of waiting for the normal interval.
func (s *Server) markBaselineMonitorsDue() {
	s.markMonitorTypesDue("service.baseline")
}

// markMonitorTypesDue queues an immediate check for monitors of the given
// types. It is used after a per-host monitoring setting changes so stale
// unknown/critical states are cleared without waiting for the next interval.
func (s *Server) markMonitorTypesDue(types ...string) {
	if len(types) == 0 {
		return
	}
	wanted := make(map[string]bool, len(types))
	for _, monitorType := range types {
		wanted[monitorType] = true
	}
	monitors, err := s.store.ListMonitors()
	if err != nil {
		return
	}
	for _, monitor := range monitors {
		if !wanted[monitor.Type] {
			continue
		}
		_ = s.store.SetMonitorChecked(monitor.ID, "1970-01-01T00:00:00Z")
	}
	select {
	case s.monitorWake <- struct{}{}:
	default:
	}
}
