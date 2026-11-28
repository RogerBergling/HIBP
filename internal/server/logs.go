package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type eventAckRequest struct {
	Note string `json:"note"`
}

func (s *Server) handleAcknowledgeHostEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid event id")
		return
	}
	var request eventAckRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	note := strings.TrimSpace(request.Note)
	if len(note) > 512 {
		writeError(w, http.StatusBadRequest, "acknowledgement note must be at most 512 characters")
		return
	}
	found, err := s.store.AcknowledgeHostEvent(id, s.auditActor(r), note,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "event-ack", "event", strconv.FormatInt(id, 10), note)
	writeJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

func (s *Server) handleUnacknowledgeHostEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid event id")
		return
	}
	if err := decodeJSON(w, r, &eventAckRequest{}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	found, err := s.store.UnacknowledgeHostEvent(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "event-unack", "event", strconv.FormatInt(id, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

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
