package server

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

type passwordRequest struct {
	Password     string `json:"password"`
	SudoPassword string `json:"sudo_password"`
}

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
	host, err := s.store.CreateHostAs(s.auditActor(r), request.host())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, host)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request hostRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	host := request.host()
	host.ID = existing.ID
	host.CreatedAt = existing.CreatedAt
	host.Status = existing.Status
	if host.OSFamily == "" {
		host.OSFamily = existing.OSFamily
	}
	if host.OSVersion == "" {
		host.OSVersion = existing.OSVersion
	}
	updated, err := s.store.UpdateHostAs(s.auditActor(r), host)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
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
	if err := s.store.DeleteHostAs(s.auditActor(r), r.PathValue("id")); err != nil {
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
	var request passwordRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err = remote.Test(ctx, s.hostTarget(host, password), remoteHostKey(key))
	if err != nil {
		var keyErr *remote.KeyError
		if errors.As(err, &keyErr) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": keyErr.Error(), "key": keyErr})
			return
		}
		_ = s.store.SetHostStatus(host.ID, "unreachable")
		_ = s.store.AddAudit(s.auditActor(r), "test-failed", "host", host.ID, err.Error())
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = s.store.SetHostStatus(host.ID, "reachable")
	_ = s.store.AddAudit(s.auditActor(r), "test", "host", host.ID, "connection and host key verified")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": host.Name})
}

type trustKeyRequest struct {
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	Password    string `json:"password"`
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
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	actual, err := remote.Probe(ctx, s.hostTarget(host, password))
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if actual.KeyType != request.KeyType || actual.Fingerprint != request.Fingerprint {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "presented host key does not match the approval", "key": actual})
		return
	}
	if err := s.store.SaveHostKeyAs(s.auditActor(r), store.HostKey{HostID: host.ID, KeyType: actual.KeyType, Fingerprint: actual.Fingerprint}); err != nil {
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

var errSudoPasswordRequired = errors.New("sudo requires a password on the target; use Setup in HIBP or enter the sudo password when prompted")
var errSudoPasswordInvalid = errors.New("sudo password was rejected by the target")

func looksLikeSudoPasswordInvalid(output string) bool {
	lower := strings.ToLower(output)
	for _, needle := range []string{"sorry, try again", "incorrect password", "incorrect password attempt", "authentication failure"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func looksLikeSudoAuthFailure(output string) bool {
	lower := strings.ToLower(output)
	for _, needle := range []string{
		"interactive authentication is required",
		"a password is required",
		"no tty present",
		"no askpass program specified",
		"a terminal is required",
		"must have a tty",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (s *Server) runHelper(ctx context.Context, host store.Host, action, sshPassword, sudoPassword string, timeout time.Duration, args ...string) (string, int, error) {
	switch action {
	case "facts", "check", "apply", "reboot", "system-info", "metrics", "docker-list", "docker-check", "docker-apply":
	default:
		return "", 0, errors.New("invalid helper action")
	}
	if action == "docker-check" || action == "docker-apply" {
		if len(args) != 1 || !dockerProjectPattern.MatchString(args[0]) {
			return "", 0, errors.New("invalid Docker project")
		}
	} else if len(args) != 0 {
		return "", 0, errors.New("unexpected helper arguments")
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		return "", 0, err
	}
	if key == nil {
		return "", 0, errors.New("host key is not trusted; test and trust the host first")
	}
	helperAction := action
	if len(args) == 1 {
		helperAction += " " + args[0]
	}
	command := "sudo -n /usr/local/libexec/hibp/hibp-helper " + helperAction
	input := ""
	if sudoPassword != "" {
		command = "sudo -S -p '' /usr/local/libexec/hibp/hibp-helper " + helperAction
		input = sudoPassword + "\n"
	}
	output, code, err := remote.RunWithInput(ctx, s.hostTarget(host, sshPassword), &remote.HostKey{KeyType: key.KeyType, Fingerprint: key.Fingerprint}, command, input, timeout)
	if err != nil {
		return output, code, err
	}
	if code != 0 && looksLikeSudoPasswordInvalid(output) {
		return output, code, errSudoPasswordInvalid
	}
	if code != 0 && looksLikeSudoAuthFailure(output) {
		return output, code, errSudoPasswordRequired
	}
	return output, code, nil
}

func (s *Server) handleFacts(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request passwordRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
	}
	output, code, err := s.runHelper(r.Context(), host, "facts", password, request.SudoPassword, 2*time.Minute)
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
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper failed", "exit_code": code, "output": output})
		return
	}
	var facts helper.Facts
	if err := json.Unmarshal([]byte(output), &facts); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper returned invalid JSON", "output": output})
		return
	}
	if err := s.store.SaveFactsAs(s.auditActor(r), host.ID, storeFactsFromHelper(facts)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "facts": facts})
}

type patchRequest struct {
	DryRun       bool   `json:"dry_run"`
	Confirm      string `json:"confirm"`
	Password     string `json:"password"`
	SudoPassword string `json:"sudo_password"`
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
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
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
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, action, password, request.SudoPassword, timeout)
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
	result := helper.Result{Action: action, OK: code == 0, ExitCode: code, Output: output}
	if err := s.store.AddAudit(s.auditActor(r), "patch-"+action, "host", host.ID, fmt.Sprintf("exit=%d", code)); err != nil {
		_ = err
	}
	writeJSON(w, http.StatusOK, result)
}

type rebootRequest struct {
	Confirm      string `json:"confirm"`
	Password     string `json:"password"`
	SudoPassword string `json:"sudo_password"`
}

func (s *Server) handleReboot(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request rebootRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.Confirm != "reboot" {
		writeError(w, http.StatusBadRequest, "confirm must be \"reboot\" to reboot the host")
		return
	}
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, "reboot", password, request.SudoPassword, 2*time.Minute)
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
	result := helper.Result{Action: "reboot", OK: code == 0, ExitCode: code, Output: output}
	if code == 0 {
		_ = s.store.SetHostStatus(host.ID, "unknown")
	}
	if err := s.store.AddAudit(s.auditActor(r), "reboot", "host", host.ID, fmt.Sprintf("exit=%d", code)); err != nil {
		_ = err
	}
	writeJSON(w, http.StatusOK, result)
}

func storeFactsFromHelper(facts helper.Facts) store.Facts {
	return store.Facts{
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
}

const maxHelperBinarySize = 100 << 20

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request passwordRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	password := ""
	if host.AuthType == "password" {
		if request.Password == "" {
			writeError(w, http.StatusBadRequest, "password is required for password authentication")
			return
		}
		password = request.Password
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if key == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "host key is not trusted; test and trust the host first", "code": "host_key_untrusted"})
		return
	}
	executable, err := os.Executable()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "locate controller binary: "+err.Error())
		return
	}
	info, err := os.Stat(executable)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat controller binary: "+err.Error())
		return
	}
	if info.Size() > maxHelperBinarySize {
		writeError(w, http.StatusInternalServerError, "controller binary is too large to install as a helper (maximum 100 MiB)")
		return
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read controller binary: "+err.Error())
		return
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, err := remote.InstallHelper(r.Context(), s.hostTarget(host, password), remoteHostKey(key), binary, request.SudoPassword)
	if errors.Is(err, remote.ErrSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, remote.ErrSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.store.AddAudit(s.auditActor(r), "bootstrap-helper", "host", host.ID, "installed restricted helper"); err != nil {
		_ = err
	}
	// The verification step returns facts output. Store it when it is clean
	// JSON so the dashboard updates immediately; setup success does not depend
	// on this best-effort parse.
	var facts helper.Facts
	if json.Unmarshal([]byte(output), &facts) == nil {
		_ = s.store.SaveFactsAs(s.auditActor(r), host.ID, storeFactsFromHelper(facts))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
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
	path := strings.TrimSpace(request.Path)
	if path == "" {
		configured, _ := s.store.BackupConfig()
		if configured == "" {
			configured = filepath.Dir(s.store.Path())
		}
		path = filepath.Join(configured, "hibp-"+time.Now().Format("2006-01-02-150405")+".bac")
	} else {
		if !filepath.IsAbs(path) {
			writeError(w, http.StatusBadRequest, "backup path must be absolute")
			return
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			path = filepath.Join(path, "hibp-"+time.Now().Format("2006-01-02-150405")+".bac")
		}
	}
	if !filepath.IsAbs(path) {
		writeError(w, http.StatusBadRequest, "backup path must be absolute")
		return
	}
	if err := s.store.Backup(path); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "backup", "database", "", path)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path, "sidecar": path + ".meta"})
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
	_ = s.store.AddAudit(s.auditActor(r), "restore", "database", "", request.DestPath)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": request.DestPath, "sidecar": request.DestPath + ".meta"})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var request importRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	result, err := s.importCSV(r.Context(), s.auditActor(r), request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
