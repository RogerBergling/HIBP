package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
)

var dockerProjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

var settingDefaults = map[string]string{
	"collector.enabled":          "1",
	"collector.facts_interval":   "12h",
	"collector.metrics_interval": "5m",
	"metrics.retention_days":     "30",
	"docker.scan_roots":          "/opt",
	"backup.directory":           "",
	"backup.retention_count":     "3",
}

func (s *Server) resolveSettings(hostID string) map[string]string {
	resolved := make(map[string]string, len(settingDefaults))
	for key, fallback := range settingDefaults {
		resolved[key] = s.store.ResolveSetting(hostID, key, fallback)
	}
	return resolved
}

func (s *Server) collectSystemInfo(ctx context.Context, host store.Host, password, sudoPassword string) (helper.SystemInfo, error) {
	output, code, err := s.runHelper(ctx, host, "system-info", password, sudoPassword, 2*time.Minute)
	if err != nil {
		return helper.SystemInfo{}, err
	}
	if code != 0 {
		return helper.SystemInfo{}, errors.New("system-info helper failed: " + strings.TrimSpace(output))
	}
	var info helper.SystemInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		return helper.SystemInfo{}, err
	}
	if err := s.store.SaveSystemInfo(host.ID, info.CollectedAt, output); err != nil {
		return helper.SystemInfo{}, err
	}
	if info.Systemd.UnitsCollected {
		if err := s.store.SaveServiceState(host.ID, info.Systemd.FailedUnits, info.Systemd.RunningUnits); err != nil {
			return helper.SystemInfo{}, err
		}
	}
	diskPercent := 0.0
	for _, disk := range info.Disks {
		if disk.Mount == "/" {
			diskPercent = disk.UsedPercent
			break
		}
	}
	if info.CollectedAt == "" {
		info.CollectedAt = crypto.Now()
	}
	_ = s.store.SaveMetrics(host.ID, store.MetricSample{
		CollectedAt: info.CollectedAt, CPUPercent: info.CPU.UsagePercent,
		MemoryPercent: info.Memory.UsedPercent, SwapPercent: info.Swap.UsedPercent,
		DiskPercent: diskPercent, Load1: info.CPU.Load1, Load5: info.CPU.Load5,
		Load15: info.CPU.Load15, UptimeSeconds: info.UptimeSeconds,
	})
	return info, nil
}

func (s *Server) collectDockerInventory(ctx context.Context, host store.Host, password, sudoPassword string) (helper.DockerInventory, error) {
	output, code, err := s.runHelper(ctx, host, "docker-list", password, sudoPassword, 2*time.Minute)
	if err != nil {
		return helper.DockerInventory{}, err
	}
	if code != 0 {
		return helper.DockerInventory{}, errors.New("docker-list helper failed: " + strings.TrimSpace(output))
	}
	var inventory helper.DockerInventory
	if err := json.Unmarshal([]byte(output), &inventory); err != nil {
		return helper.DockerInventory{}, err
	}
	projects := make([]store.DockerProject, 0, len(inventory.Projects))
	for _, project := range inventory.Projects {
		projects = append(projects, store.DockerProject{
			HostID: host.ID, Name: project.Name, Status: project.Status,
			ConfigFiles: project.ConfigFiles, WorkingDir: project.WorkingDir,
		})
	}
	containers := make([]store.DockerContainer, 0, len(inventory.Containers))
	for _, container := range inventory.Containers {
		containers = append(containers, store.DockerContainer{
			HostID: host.ID, ContainerID: container.ID, Name: container.Name,
			Project: container.Project, Service: container.Service, Image: container.Image,
			State: container.State, Status: container.Status, Health: container.Health,
			Ports: container.Ports, CreatedAt: container.CreatedAt,
		})
	}
	if err := s.store.SaveDockerInventory(host.ID, projects, containers); err != nil {
		return helper.DockerInventory{}, err
	}
	return inventory, nil
}

func (s *Server) systemInfoRequest(w http.ResponseWriter, r *http.Request) (store.Host, string, string, bool) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return store.Host{}, "", "", false
	}
	var request passwordRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return store.Host{}, "", "", false
		}
	}
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return store.Host{}, "", "", false
		}
		password = request.Password
	}
	return host, password, request.SudoPassword, true
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	host, password, sudoPassword, ok := s.systemInfoRequest(w, r)
	if !ok {
		return
	}
	info, err := s.collectSystemInfo(r.Context(), host, password, sudoPassword)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "system-info", "host", host.ID, info.OSPrettyName)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "system_info": info})
}

func (s *Server) handleDockerList(w http.ResponseWriter, r *http.Request) {
	host, password, sudoPassword, ok := s.systemInfoRequest(w, r)
	if !ok {
		return
	}
	inventory, err := s.collectDockerInventory(r.Context(), host, password, sudoPassword)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-list", "host", host.ID, strconv.Itoa(len(inventory.Containers))+" containers")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "docker": inventory})
}

type dockerActionRequest struct {
	Project      string `json:"project"`
	Confirm      string `json:"confirm"`
	Password     string `json:"password"`
	SudoPassword string `json:"sudo_password"`
}

func (s *Server) dockerActionRequest(w http.ResponseWriter, r *http.Request, requireConfirm bool) (store.Host, dockerActionRequest, bool) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return store.Host{}, dockerActionRequest{}, false
	}
	var request dockerActionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return store.Host{}, dockerActionRequest{}, false
	}
	request.Project = strings.TrimSpace(request.Project)
	if !dockerProjectPattern.MatchString(request.Project) {
		writeError(w, http.StatusBadRequest, "invalid Docker project name")
		return store.Host{}, dockerActionRequest{}, false
	}
	if requireConfirm && request.Confirm != "apply" {
		writeError(w, http.StatusBadRequest, "confirm must be \"apply\" for a Docker update")
		return store.Host{}, dockerActionRequest{}, false
	}
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return store.Host{}, dockerActionRequest{}, false
		}
	}
	return host, request, true
}

func (s *Server) handleDockerCheck(w http.ResponseWriter, r *http.Request) {
	host, request, ok := s.dockerActionRequest(w, r, false)
	if !ok {
		return
	}
	output, code, err := s.runHelper(r.Context(), host, "docker-check", request.Password, request.SudoPassword, 15*time.Minute, request.Project)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if code != 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "docker-check helper failed", "exit_code": code, "output": output})
		return
	}
	var result helper.DockerCheckResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid docker-check result", "output": output})
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-check", "host", host.ID, "project="+request.Project)
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "result": result})
}

func (s *Server) handleDockerApply(w http.ResponseWriter, r *http.Request) {
	host, request, ok := s.dockerActionRequest(w, r, true)
	if !ok {
		return
	}
	output, code, err := s.runHelper(r.Context(), host, "docker-apply", request.Password, request.SudoPassword, 15*time.Minute, request.Project)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if code != 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "docker-apply helper failed", "exit_code": code, "output": output})
		return
	}
	var result helper.DockerApplyResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid docker-apply result", "output": output})
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-apply", "host", host.ID, "project="+request.Project)
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "result": result})
}

type dockerUpdateAllRequest struct {
	Confirm      string `json:"confirm"`
	Password     string `json:"password"`
	SudoPassword string `json:"sudo_password"`
}

func (s *Server) handleDockerUpdateAll(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request dockerUpdateAllRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.Confirm != "update" {
		writeError(w, http.StatusBadRequest, "confirm must be \"update\" for a Docker bulk update")
		return
	}
	if host.AuthType == "password" && request.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required for password authentication")
		return
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, "docker-update-all", request.Password, request.SudoPassword, 2*time.Hour)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, "docker-update-all", host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if code != 0 {
		s.auditHostActionFailure(r, "docker-update-all", host.ID, errors.New(strings.TrimSpace(output)))
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "docker-update-all helper failed", "exit_code": code, "output": output})
		return
	}
	var result helper.DockerUpdateAllResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "invalid docker-update-all result", "output": output})
		return
	}
	for _, project := range result.Projects {
		_ = s.store.AddAudit(s.auditActor(r), "docker-update-all", "host", host.ID,
			fmt.Sprintf("project=%s action=%s ok=%t", project.Name, project.Action, project.OK))
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-update-all", "host", host.ID,
		fmt.Sprintf("updated=%d skipped=%d failed=%d", result.Updated, result.Skipped, result.Failed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "result": result})
}

func (s *Server) handleHostDetails(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	key, _ := s.store.GetHostKey(host.ID)
	host.TrustedKey = key
	snapshot, _ := s.store.GetSystemInfo(host.ID)
	var systemInfo any
	if snapshot.PayloadJSON != "" {
		_ = json.Unmarshal([]byte(snapshot.PayloadJSON), &systemInfo)
	}
	metrics, _ := s.store.ListMetrics(host.ID, 2880)
	projects, containers, _ := s.store.GetDockerInventory(host.ID)
	settings := s.resolveSettings(host.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"host":              host,
		"system_info":       systemInfo,
		"metrics":           metrics,
		"docker_projects":   projects,
		"docker_containers": containers,
		"settings":          settings,
		"settings_defaults": settingDefaults,
	})
}

type settingsRequest struct {
	Scope    string            `json:"scope"`
	HostID   string            `json:"host_id"`
	Settings map[string]string `json:"settings"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	fleet, err := s.store.ListSettings("fleet")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hostSettings := map[string]string{}
	if hostID != "" {
		hostSettings, err = s.store.ListSettings("host:" + hostID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"fleet":    fleet,
		"host":     hostSettings,
		"resolved": s.resolveSettings(hostID),
		"defaults": settingDefaults,
	})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var request settingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	scope := "fleet"
	if request.Scope == "host" {
		if strings.TrimSpace(request.HostID) == "" {
			writeError(w, http.StatusBadRequest, "host_id is required for host settings")
			return
		}
		if _, err := s.store.GetHost(request.HostID); err != nil {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		scope = "host:" + request.HostID
	} else if request.Scope != "" && request.Scope != "fleet" {
		writeError(w, http.StatusBadRequest, "scope must be fleet or host")
		return
	}
	for key, value := range request.Settings {
		if _, ok := settingDefaults[key]; !ok {
			writeError(w, http.StatusBadRequest, "unknown setting: "+key)
			return
		}
		if scope != "fleet" && (key == "backup.directory" || key == "backup.retention_count") {
			writeError(w, http.StatusBadRequest, key+" is a fleet-level backup setting")
			return
		}
		if value == "" {
			if err := s.store.DeleteSetting(scope, key); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			continue
		}
		if err := validateSetting(key, value); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.store.SetSetting(scope, key, value); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_ = s.store.AddAudit(s.auditActor(r), "settings-update", "settings", scope, "updated")
	s.handleGetSettings(w, r)
}

func validateSetting(key, value string) error {
	switch key {
	case "collector.enabled":
		if value != "0" && value != "1" {
			return errors.New("collector.enabled must be 0 or 1")
		}
	case "collector.facts_interval", "collector.metrics_interval":
		duration, err := time.ParseDuration(value)
		if err != nil || duration < 10*time.Second || duration > 7*24*time.Hour {
			return errors.New(key + " must be a duration between 10s and 168h")
		}
	case "metrics.retention_days":
		days, err := strconv.Atoi(value)
		if err != nil || days < 1 || days > 3650 {
			return errors.New("metrics.retention_days must be between 1 and 3650")
		}
	case "docker.scan_roots":
		if strings.TrimSpace(value) == "" {
			return errors.New("docker.scan_roots must not be empty")
		}
	case "backup.directory":
		if value != "" && !filepath.IsAbs(value) {
			return errors.New("backup.directory must be an absolute path")
		}
	case "backup.retention_count":
		count, err := strconv.Atoi(value)
		if err != nil || count < 1 || count > 100 {
			return errors.New("backup.retention_count must be between 1 and 100")
		}
	}
	return nil
}
