package server

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

type hostRequest struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"`
	KeyPath   string `json:"key_path"`
	Tags      string `json:"tags"`
	GroupName string `json:"group_name"`
	CMDBCIID  string `json:"cmdb_ci_id"`
}

func (h hostRequest) host() store.Host {
	return store.Host{
		Name: h.Name, Address: h.Address, Port: h.Port, Username: h.Username,
		AuthType: h.AuthType, KeyPath: h.KeyPath, Tags: h.Tags,
		GroupName: h.GroupName, CMDBCIID: h.CMDBCIID,
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	hosts, err := s.store.CountHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	entries, err := s.store.CountAudit()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       s.version,
		"hosts":         hosts,
		"audit_entries": entries,
		"time":          crypto.Now(),
	})
}

func (s *Server) handleListHosts(w http.ResponseWriter, _ *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hosts == nil {
		hosts = []store.Host{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var request hostRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	host, err := s.store.CreateHost(request.host())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, host)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	key, _ := s.store.GetHostKey(host.ID)
	host.TrustedKey = key
	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteHost(r.PathValue("id")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleTestHost(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err = remote.Test(ctx, s.hostTarget(host), remoteHostKey(key))
	if err != nil {
		var keyErr *remote.KeyError
		if errors.As(err, &keyErr) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": keyErr.Error(), "key": keyErr})
			return
		}
		_ = s.store.SetHostStatus(host.ID, "unreachable")
		_ = s.store.AddAudit(s.actor, "test-failed", "host", host.ID, err.Error())
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.store.SetHostStatus(host.ID, "reachable")
	_ = s.store.AddAudit(s.actor, "test", "host", host.ID, "connection and host key verified")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": host.Name})
}

type trustKeyRequest struct {
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleTrustKey(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request trustKeyRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.KeyType == "" || request.Fingerprint == "" {
		writeError(w, http.StatusBadRequest, "key_type and fingerprint are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	actual, err := remote.Probe(ctx, s.hostTarget(host))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if actual.KeyType != request.KeyType || actual.Fingerprint != request.Fingerprint {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "presented host key does not match the approval", "key": actual})
		return
	}
	if err := s.store.SaveHostKey(store.HostKey{HostID: host.ID, KeyType: actual.KeyType, Fingerprint: actual.Fingerprint}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": actual})
}

func remoteHostKey(key *store.HostKey) *remote.HostKey {
	if key == nil {
		return nil
	}
	return &remote.HostKey{KeyType: key.KeyType, Fingerprint: key.Fingerprint}
}

func (s *Server) runHelper(ctx context.Context, host store.Host, action string, timeout time.Duration) (string, int, error) {
	switch action {
	case "facts", "check", "apply":
	default:
		return "", 0, errors.New("invalid helper action")
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		return "", 0, err
	}
	if key == nil {
		return "", 0, errors.New("host key is not trusted; test and trust the host first")
	}
	command := "sudo -n /usr/local/libexec/hibp/hibp-helper " + action
	return remote.Run(ctx, s.hostTarget(host), &remote.HostKey{KeyType: key.KeyType, Fingerprint: key.Fingerprint}, command, timeout)
}

func (s *Server) handleFacts(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	output, code, err := s.runHelper(r.Context(), host, "facts", 2*time.Minute)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if code != 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper failed", "exit_code": code, "output": output})
		return
	}
	var facts helper.Facts
	if err := json.Unmarshal([]byte(output), &facts); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper returned invalid JSON", "output": output})
		return
	}
	stored := store.Facts{
		CollectedAt:    crypto.Now(),
		UptimeSeconds:  facts.UptimeSeconds,
		BootTime:       facts.BootTime,
		Kernel:         facts.Kernel,
		OSPrettyName:   facts.OSPrettyName,
		PackageManager: facts.PackageManager,
		RebootRequired: facts.RebootRequired,
		DiskFreeBytes:  facts.DiskFreeBytes,
		TimeSyncOK:     facts.TimeSyncOK,
		PendingUpdates: facts.PendingUpdates,
	}
	if err := s.store.SaveFacts(host.ID, stored); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "facts": facts})
}

type patchRequest struct {
	DryRun  bool   `json:"dry_run"`
	Confirm string `json:"confirm"`
}

func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request patchRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	action := "check"
	timeout := 10 * time.Minute
	if !request.DryRun {
		if request.Confirm != "apply" {
			writeError(w, http.StatusBadRequest, "confirm must be \"apply\" for a real patch run")
			return
		}
		action = "apply"
		timeout = 45 * time.Minute
	}
	output, code, err := s.runHelper(r.Context(), host, action, timeout)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result := helper.Result{Action: action, OK: code == 0, ExitCode: code, Output: output}
	if err := s.store.AddAudit(s.actor, "patch-"+action, "host", host.ID, fmt.Sprintf("exit=%d", code)); err != nil {
		_ = err
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	entries, err := s.store.ListAudit(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, _ *http.Request) {
	if err := s.store.VerifyAudit(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleExportHosts(w http.ResponseWriter, _ *http.Request) {
	hosts, err := s.store.ListHosts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hibp-hosts.csv"`)
	writer := csv.NewWriter(w)
	defer writer.Flush()
	_ = writer.Write([]string{"name", "address", "port", "username", "auth_type", "os", "status", "pending_updates", "reboot_required", "uptime_seconds", "last_check", "tags", "group", "cmdb_ci_id"})
	for _, host := range hosts {
		pending, reboot, uptime, last := "", "", "", ""
		if host.Facts != nil {
			pending = strconv.Itoa(host.Facts.PendingUpdates)
			reboot = strconv.FormatBool(host.Facts.RebootRequired)
			uptime = strconv.FormatInt(host.Facts.UptimeSeconds, 10)
			last = host.Facts.CollectedAt
		}
		_ = writer.Write([]string{
			neutralizeCSV(host.Name), neutralizeCSV(host.Address), strconv.Itoa(host.Port),
			neutralizeCSV(host.Username), host.AuthType, neutralizeCSV(host.OSFamily + " " + host.OSVersion),
			host.Status, pending, reboot, uptime, last, neutralizeCSV(host.Tags),
			neutralizeCSV(host.GroupName), neutralizeCSV(host.CMDBCIID),
		})
	}
}

func neutralizeCSV(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}

type backupRequest struct {
	Path string `json:"path"`
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	var request backupRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !filepath.IsAbs(request.Path) {
		writeError(w, http.StatusBadRequest, "backup path must be absolute")
		return
	}
	if err := s.store.Backup(request.Path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddAudit(s.actor, "backup", "database", "", request.Path)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": request.Path, "sidecar": request.Path + ".meta"})
}

type restoreRequest struct {
	BackupPath string `json:"backup_path"`
	DestPath   string `json:"dest_path"`
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var request restoreRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if !filepath.IsAbs(request.BackupPath) || !filepath.IsAbs(request.DestPath) {
		writeError(w, http.StatusBadRequest, "backup_path and dest_path must be absolute")
		return
	}
	if err := s.store.Restore(request.BackupPath, request.DestPath); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddAudit(s.actor, "restore", "database", "", request.DestPath)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": request.DestPath, "sidecar": request.DestPath + ".meta"})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var request importRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	result, err := s.importCSV(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
