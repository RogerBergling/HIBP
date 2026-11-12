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

func dockerCheckStatus(check helper.DockerCheckResult) (string, string) {
	if !check.OK {
		summary := strings.TrimSpace(check.Error)
		if summary == "" {
			summary = "docker compose pull failed"
		}
		return "failed", summary
	}
	var changed []string
	for _, service := range check.Services {
		switch service.Status {
		case "new-image", "image-updated", "container-stale":
			changed = append(changed, service.Service)
		}
	}
	if len(changed) > 0 {
		return "update-available", "Update available: " + strings.Join(changed, ", ")
	}
	return "up-to-date", "Up to date"
}

func (s *Server) saveDockerCheck(hostID, project string, check helper.DockerCheckResult) {
	status, summary := dockerCheckStatus(check)
	_ = s.store.SaveDockerProjectCheck(store.DockerProjectCheck{
		HostID: hostID, Project: project, Status: status, Summary: summary,
		Error: check.Error,
	})
}

func (s *Server) saveDockerApplyStatus(hostID, project string, apply helper.DockerApplyResult) {
	status := "updated"
	summary := "Compose recreate completed"
	if !apply.OK {
		status = "failed"
		summary = apply.Error
		if summary == "" {
			summary = "docker compose up failed"
		}
	}
	_ = s.store.SaveDockerProjectCheck(store.DockerProjectCheck{
		HostID: hostID, Project: project, Status: status, Summary: summary, Error: apply.Error,
	})
}

func (s *Server) saveDockerProjectUpdate(hostID string, project helper.DockerProjectUpdateResult) {
	switch project.Action {
	case "updated":
		summary := "Compose recreate completed"
		if project.Check != nil {
			if status, checkSummary := dockerCheckStatus(*project.Check); status == "update-available" {
				summary = "Recreated: " + strings.TrimPrefix(checkSummary, "Update available: ")
			}
		}
		_ = s.store.SaveDockerProjectCheck(store.DockerProjectCheck{
			HostID: hostID, Project: project.Name, Status: "updated", Summary: summary, Error: project.Error,
		})
	case "no-change":
		_ = s.store.SaveDockerProjectCheck(store.DockerProjectCheck{
			HostID: hostID, Project: project.Name, Status: "up-to-date", Summary: "Up to date", Error: project.Error,
		})
	default:
		_ = s.store.SaveDockerProjectCheck(store.DockerProjectCheck{
			HostID: hostID, Project: project.Name, Status: "failed", Summary: project.Error, Error: project.Error,
		})
	}
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
	s.saveDockerCheck(host.ID, request.Project, result)
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
	s.saveDockerApplyStatus(host.ID, request.Project, result)
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
		s.saveDockerProjectUpdate(host.ID, project)
		_ = s.store.AddAudit(s.auditActor(r), "docker-update-all", "host", host.ID,
			fmt.Sprintf("project=%s action=%s ok=%t", project.Name, project.Action, project.OK))
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-update-all", "host", host.ID,
		fmt.Sprintf("updated=%d skipped=%d failed=%d", result.Updated, result.Skipped, result.Failed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.OK, "result": result})
}

type dockerCheckAllResult struct {
	Project string                    `json:"project"`
	Status  string                    `json:"status"`
	Summary string                    `json:"summary"`
	Error   string                    `json:"error,omitempty"`
	Result  *helper.DockerCheckResult `json:"result,omitempty"`
}

func (s *Server) handleDockerCheckAll(w http.ResponseWriter, r *http.Request) {
	host, password, sudoPassword, ok := s.systemInfoRequest(w, r)
	if !ok {
		return
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
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
	results := make([]dockerCheckAllResult, 0, len(inventory.Projects))
	updates := 0
	failed := 0
	started := time.Now()
	for _, project := range inventory.Projects {
		entry := dockerCheckAllResult{Project: project.Name}
		output, code, runErr := s.runHelper(r.Context(), host, "docker-check", password, sudoPassword, 15*time.Minute, project.Name)
		if errors.Is(runErr, errSudoPasswordInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": runErr.Error(), "code": "sudo_password_invalid"})
			return
		}
		if errors.Is(runErr, errSudoPasswordRequired) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": runErr.Error(), "code": "sudo_password_required"})
			return
		}
		if runErr != nil {
			entry.Status = "failed"
			entry.Error = runErr.Error()
			entry.Summary = runErr.Error()
			failed++
			results = append(results, entry)
			s.saveDockerCheck(host.ID, project.Name, helper.DockerCheckResult{Project: project.Name, OK: false, Error: runErr.Error()})
			continue
		}
		if code != 0 {
			entry.Status = "failed"
			entry.Error = strings.TrimSpace(output)
			entry.Summary = entry.Error
			failed++
			results = append(results, entry)
			s.saveDockerCheck(host.ID, project.Name, helper.DockerCheckResult{Project: project.Name, OK: false, Error: entry.Error})
			continue
		}
		var check helper.DockerCheckResult
		if err := json.Unmarshal([]byte(output), &check); err != nil {
			entry.Status = "failed"
			entry.Error = "invalid docker-check result"
			entry.Summary = entry.Error
			failed++
			results = append(results, entry)
			s.saveDockerCheck(host.ID, project.Name, helper.DockerCheckResult{Project: project.Name, OK: false, Error: entry.Error})
			continue
		}
		entry.Result = &check
		entry.Status, entry.Summary = dockerCheckStatus(check)
		if entry.Status == "update-available" {
			updates++
		}
		if entry.Status == "failed" {
			failed++
		}
		s.saveDockerCheck(host.ID, project.Name, check)
		results = append(results, entry)
		_ = s.store.AddAudit(s.auditActor(r), "docker-check", "host", host.ID,
			fmt.Sprintf("project=%s status=%s", project.Name, entry.Status))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": failed == 0, "checked": len(results), "updates": updates,
		"failed": failed, "duration_seconds": time.Since(started).Seconds(),
		"results": results,
	})
}

type dockerUpdateSelectedRequest struct {
	Projects     []string `json:"projects"`
	Confirm      string   `json:"confirm"`
	Password     string   `json:"password"`
	SudoPassword string   `json:"sudo_password"`
}

func (s *Server) handleDockerUpdateSelected(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request dockerUpdateSelectedRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.Confirm != "update" {
		writeError(w, http.StatusBadRequest, "confirm must be \"update\" for a Docker update")
		return
	}
	if host.AuthType == "password" && request.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required for password authentication")
		return
	}
	known, _, err := s.store.GetDockerInventory(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	knownProjects := make(map[string]bool, len(known))
	for _, project := range known {
		knownProjects[project.Name] = true
	}
	selected := make([]string, 0, len(request.Projects))
	seen := make(map[string]bool)
	for _, project := range request.Projects {
		project = strings.TrimSpace(project)
		if !dockerProjectPattern.MatchString(project) {
			writeError(w, http.StatusBadRequest, "invalid Docker project name")
			return
		}
		if !knownProjects[project] {
			writeError(w, http.StatusBadRequest, "unknown Docker project: "+project)
			return
		}
		if seen[project] {
			continue
		}
		seen[project] = true
		selected = append(selected, project)
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one Docker project")
		return
	}
	if len(selected) > 100 {
		writeError(w, http.StatusBadRequest, "too many Docker projects selected")
		return
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	results := make([]helper.DockerProjectUpdateResult, 0, len(selected))
	updated, skipped, failed := 0, 0, 0
	started := time.Now()
	for _, project := range selected {
		entry := helper.DockerProjectUpdateResult{Name: project}
		output, code, checkErr := s.runHelper(r.Context(), host, "docker-check", request.Password, request.SudoPassword, 15*time.Minute, project)
		if errors.Is(checkErr, errSudoPasswordInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": checkErr.Error(), "code": "sudo_password_invalid"})
			return
		}
		if errors.Is(checkErr, errSudoPasswordRequired) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": checkErr.Error(), "code": "sudo_password_required"})
			return
		}
		if checkErr != nil {
			entry.Action = "failed"
			entry.Error = checkErr.Error()
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		if code != 0 {
			entry.Action = "failed"
			entry.Error = strings.TrimSpace(output)
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		var check helper.DockerCheckResult
		if err := json.Unmarshal([]byte(output), &check); err != nil {
			entry.Action = "failed"
			entry.Error = "invalid docker-check result"
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		entry.Check = &check
		s.saveDockerCheck(host.ID, project, check)
		if !check.OK {
			entry.Action = "failed"
			entry.Error = check.Error
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		if !helper.DockerCheckNeedsApply(check) {
			entry.Action = "no-change"
			entry.OK = true
			s.saveDockerProjectUpdate(host.ID, entry)
			skipped++
			results = append(results, entry)
			continue
		}
		applyOutput, applyCode, applyErr := s.runHelper(r.Context(), host, "docker-apply", request.Password, request.SudoPassword, 15*time.Minute, project)
		if errors.Is(applyErr, errSudoPasswordInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": applyErr.Error(), "code": "sudo_password_invalid"})
			return
		}
		if errors.Is(applyErr, errSudoPasswordRequired) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": applyErr.Error(), "code": "sudo_password_required"})
			return
		}
		if applyErr != nil {
			entry.Action = "failed"
			entry.Error = applyErr.Error()
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		if applyCode != 0 {
			entry.Action = "failed"
			entry.Error = strings.TrimSpace(applyOutput)
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		var apply helper.DockerApplyResult
		if err := json.Unmarshal([]byte(applyOutput), &apply); err != nil {
			entry.Action = "failed"
			entry.Error = "invalid docker-apply result"
			s.saveDockerProjectUpdate(host.ID, entry)
			failed++
			results = append(results, entry)
			continue
		}
		entry.Apply = &apply
		entry.OK = apply.OK
		if apply.OK {
			entry.Action = "updated"
			updated++
		} else {
			entry.Action = "failed"
			entry.Error = apply.Error
			failed++
		}
		s.saveDockerProjectUpdate(host.ID, entry)
		results = append(results, entry)
		_ = s.store.AddAudit(s.auditActor(r), "docker-update-selected", "host", host.ID,
			fmt.Sprintf("project=%s action=%s ok=%t", project, entry.Action, entry.OK))
	}
	_ = s.store.AddAudit(s.auditActor(r), "docker-update-selected", "host", host.ID,
		fmt.Sprintf("updated=%d skipped=%d failed=%d", updated, skipped, failed))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": failed == 0, "updated": updated, "skipped": skipped,
		"failed": failed, "duration_seconds": time.Since(started).Seconds(),
		"results": results,
	})
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
	checks, _ := s.store.ListDockerProjectChecks(host.ID)
	settings := s.resolveSettings(host.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"host":              host,
		"system_info":       systemInfo,
		"metrics":           metrics,
		"docker_projects":   projects,
		"docker_containers": containers,
		"docker_checks":     checks,
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
