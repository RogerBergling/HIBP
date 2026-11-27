package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
)

type agentView struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	HostName  string `json:"host_name"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	LastSeen  string `json:"last_seen"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at"`
}

type agentCreateResponse struct {
	Agent agentView `json:"agent"`
	Token string    `json:"token"`
}

type agentHeartbeat struct {
	Platform string `json:"platform"`
	Version  string `json:"version"`
}

type agentServices struct {
	Running []string `json:"running"`
	Failed  []string `json:"failed"`
}

type agentSnapshot struct {
	Facts    *helper.Facts           `json:"facts"`
	Services *agentServices          `json:"services"`
	Docker   *helper.DockerInventory `json:"docker"`
}

type agentEvents struct {
	Events []helper.Event `json:"events"`
}

func agentToken() (string, string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(buffer)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}

func agentHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Server) agentView(agent store.Agent) agentView {
	host, _ := s.store.GetHost(agent.HostID)
	return agentView{
		ID: agent.ID, HostID: agent.HostID, HostName: host.Name, Name: agent.Name,
		Platform: agent.Platform, Version: agent.Version, LastSeen: agent.LastSeen,
		CreatedAt: agent.CreatedAt, RevokedAt: agent.RevokedAt,
	}
}

func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if host.AuthType != "agent" {
		writeError(w, http.StatusBadRequest, "host auth_type must be agent before creating an agent token")
		return
	}
	token, hash, err := agentToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	agent, err := s.store.CreateAgent(host.ID, host.Name, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "agent-token-create", "host", host.ID, host.Name)
	writeJSON(w, http.StatusCreated, agentCreateResponse{Agent: s.agentView(agent), Token: token})
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	agent, err := s.store.GetAgentByHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": s.agentView(agent)})
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	hostID := r.PathValue("id")
	if err := s.store.RevokeAgent(hostID); err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "agent-token-revoke", "host", hostID, "revoked")
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (s *Server) authenticateAgent(w http.ResponseWriter, r *http.Request) (store.Agent, store.Host, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		writeError(w, http.StatusUnauthorized, "agent token is required")
		return store.Agent{}, store.Host{}, false
	}
	agent, err := s.store.GetAgentByTokenHash(agentHash(strings.TrimSpace(header[7:])))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid agent token")
		return store.Agent{}, store.Host{}, false
	}
	host, err := s.store.GetHost(agent.HostID)
	if err != nil || host.AuthType != "agent" {
		writeError(w, http.StatusForbidden, "agent host is not available")
		return store.Agent{}, store.Host{}, false
	}
	return agent, host, true
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	agent, _, ok := s.authenticateAgent(w, r)
	if !ok {
		return
	}
	var request agentHeartbeat
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	if err := s.store.TouchAgent(agent.ID, request.Platform, request.Version); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	_, host, ok := s.authenticateAgent(w, r)
	if !ok {
		return
	}
	var request agentEvents
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	stored := make([]store.HostEvent, 0, len(request.Events))
	for _, event := range request.Events {
		stored = append(stored, store.HostEvent{
			EventID: event.EventID, Source: event.Source, Category: event.Category,
			Severity: event.Severity, Unit: event.Unit, Username: event.Username,
			RemoteIP: event.RemoteIP, Message: event.Message, OccurredAt: event.OccurredAt,
		})
	}
	if err := s.store.AddHostEvents(host.ID, stored); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": len(stored)})
}

func (s *Server) handleAgentSnapshot(w http.ResponseWriter, r *http.Request) {
	agent, host, ok := s.authenticateAgent(w, r)
	if !ok {
		return
	}
	var request agentSnapshot
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.Facts != nil {
		if request.Facts.Agent.Version == "" {
			request.Facts.Agent.Version = agent.Version
		}
		if err := s.store.SaveFactsAs("agent", host.ID, storeFactsFromHelper(*request.Facts)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if request.Services != nil {
		if err := s.store.SaveServiceState(host.ID, request.Services.Failed, request.Services.Running); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.store.EnsureServiceBaseline(host.ID, request.Services.Running); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if request.Docker != nil && request.Docker.Available {
		projects := make([]store.DockerProject, 0, len(request.Docker.Projects))
		for _, project := range request.Docker.Projects {
			projects = append(projects, store.DockerProject{
				Name: project.Name, Status: project.Status, ConfigFiles: project.ConfigFiles,
				WorkingDir: project.WorkingDir,
			})
		}
		containers := make([]store.DockerContainer, 0, len(request.Docker.Containers))
		for _, container := range request.Docker.Containers {
			containers = append(containers, store.DockerContainer{
				ContainerID: container.ID, Name: container.Name, Image: container.Image,
				Project: container.Project, Service: container.Service, State: container.State,
				Status: container.Status, Health: container.Health, Ports: container.Ports,
				CreatedAt: container.CreatedAt,
			})
		}
		if err := s.store.SaveDockerInventory(host.ID, projects, containers); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// EncodeAgentSnapshot is used by tests and the agent client.
func EncodeAgentSnapshot(snapshot agentSnapshot) ([]byte, error) {
	return json.Marshal(snapshot)
}
