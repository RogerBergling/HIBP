package server

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) handleClearEvents(w http.ResponseWriter, r *http.Request) {
	hostID := strings.TrimSpace(r.URL.Query().Get("host_id"))
	if hostID != "" {
		if _, err := s.store.GetHost(hostID); err != nil {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
	}
	deleted, err := s.store.ClearHostEvents(hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	entityID := hostID
	if entityID == "" {
		entityID = "all"
	}
	_ = s.store.AddAudit(s.auditActor(r), "events-clear", "events", entityID,
		fmt.Sprintf("deleted=%d", deleted))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

func (s *Server) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.store.ClearAlertEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "alerts-clear", "alerts", "all",
		fmt.Sprintf("deleted=%d", deleted))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}
