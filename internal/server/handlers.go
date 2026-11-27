package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
	Name              string `json:"name"`
	Address           string `json:"address"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
	AuthType          string `json:"auth_type"`
	KeyPath           string `json:"key_path"`
	ProxyJumpAddress  string `json:"proxy_jump_address"`
	ProxyJumpPort     int    `json:"proxy_jump_port"`
	ProxyJumpUsername string `json:"proxy_jump_username"`
	ProxyJumpKeyPath  string `json:"proxy_jump_key_path"`
	Tags              string `json:"tags"`
	GroupName         string `json:"group_name"`
	CMDBCIID          string `json:"cmdb_ci_id"`
	APTUpgradeMode    string `json:"apt_upgrade_mode"`
}

func (h hostRequest) host() store.Host {
	host := store.Host{
		Name: h.Name, Address: h.Address, Port: h.Port, Username: h.Username,
		AuthType: h.AuthType, KeyPath: h.KeyPath, Tags: h.Tags,
		GroupName: h.GroupName, CMDBCIID: h.CMDBCIID, APTUpgradeMode: h.APTUpgradeMode,
	}
	if strings.TrimSpace(h.ProxyJumpAddress) != "" {
		host.ProxyJump = &store.ProxyJump{
			Address: h.ProxyJumpAddress, Port: h.ProxyJumpPort,
			Username: h.ProxyJumpUsername, KeyPath: h.ProxyJumpKeyPath,
		}
	}
	return host
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
		"version":       s.build.Version,
		"build":         s.build,
		"hosts":         hosts,
		"audit_entries": entries,
		"time":          crypto.Now(),
		"controller":    controllerStatus(),
		"demo":          s.demo != nil,
	})
}

// controllerStatus describes the host running this server. The UI uses it to
// keep the controller out of bulk reboot batches.
func controllerStatus() map[string]any {
	hostname, _ := os.Hostname()
	addresses := []string{}
	if values, err := net.InterfaceAddrs(); err == nil {
		for _, address := range values {
			switch value := address.(type) {
			case *net.IPNet:
				addresses = append(addresses, value.IP.String())
			case *net.IPAddr:
				addresses = append(addresses, value.IP.String())
			}
		}
	}
	return map[string]any{"hostname": hostname, "addresses": addresses}
}

func controllerName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimSuffix(value, ".")
}

// controllerNames returns the names and addresses that identify this server.
// Short hostnames are included so an inventory entry using a short name still
// matches a controller known by its FQDN, and vice versa.
func controllerNames() map[string]bool {
	names := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	add := func(value string) {
		value = controllerName(value)
		if value == "" {
			return
		}
		if ip := net.ParseIP(value); ip != nil {
			names[ip.String()] = true
			return
		}
		names[value] = true
		if index := strings.Index(value, "."); index > 0 {
			names[value[:index]] = true
		}
	}
	status := controllerStatus()
	if hostname, ok := status["hostname"].(string); ok {
		add(hostname)
	}
	if addresses, ok := status["addresses"].([]string); ok {
		for _, address := range addresses {
			add(address)
		}
	}
	return names
}

func (s *Server) isControllerHost(host store.Host) bool {
	names := controllerNames()
	for _, value := range []string{host.Name, host.Address} {
		value = controllerName(value)
		if value == "" {
			continue
		}
		if names[value] {
			return true
		}
		if ip := net.ParseIP(value); ip != nil && names[ip.String()] {
			return true
		}
	}
	return false
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
	if strings.TrimSpace(host.APTUpgradeMode) == "" {
		host.APTUpgradeMode = existing.APTUpgradeMode
	}
	if host.OSFamily == "" {
		host.OSFamily = existing.OSFamily
	}
	if host.OSVersion == "" {
		host.OSVersion = existing.OSVersion
	}
	if host.ProxyJump != nil && existing.ProxyJump != nil &&
		host.ProxyJump.Address == existing.ProxyJump.Address && host.ProxyJump.Port == existing.ProxyJump.Port {
		host.ProxyJump.KeyType = existing.ProxyJump.KeyType
		host.ProxyJump.Fingerprint = existing.ProxyJump.Fingerprint
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
	if s.demo != nil {
		err = s.demo.TestHost(ctx, host, password)
	} else {
		err = remote.Test(ctx, s.hostTarget(host, password), remoteHostKey(key))
	}
	if err != nil {
		var keyErr *remote.KeyError
		if errors.As(err, &keyErr) {
			action := "host-key-" + keyErr.Kind
			if keyErr.Scope == "jump" {
				action = "jump-key-" + keyErr.Kind
			}
			_ = s.store.AddAudit(s.auditActor(r), action, "host", host.ID,
				fmt.Sprintf("presented=%s %s expected=%s %s", keyErr.KeyType, keyErr.Fingerprint, keyErr.ExpectedType, keyErr.ExpectedFingerprint))
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
	var actual remote.HostKey
	if s.demo != nil {
		actual, err = s.demo.ProbeHost(ctx, host, password)
	} else {
		actual, err = remote.Probe(ctx, s.hostTarget(host, password))
	}
	if err != nil {
		var keyErr *remote.KeyError
		if errors.As(err, &keyErr) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": keyErr.Error(), "key": keyErr})
			return
		}
		s.auditHostActionFailure(r, "trust-key", host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if actual.KeyType != request.KeyType || actual.Fingerprint != request.Fingerprint {
		_ = s.store.AddAudit(s.auditActor(r), "trust-key-failed", "host", host.ID,
			fmt.Sprintf("presented=%s %s approved=%s %s", actual.KeyType, actual.Fingerprint, request.KeyType, request.Fingerprint))
		writeJSON(w, http.StatusConflict, map[string]any{"error": "presented host key does not match the approval", "key": actual})
		return
	}
	if err := s.store.SaveHostKeyAs(s.auditActor(r), store.HostKey{HostID: host.ID, KeyType: actual.KeyType, Fingerprint: actual.Fingerprint}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": actual})
}

func (s *Server) handleTrustJumpKey(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if host.ProxyJump == nil {
		writeError(w, http.StatusBadRequest, "host has no proxy jump configured")
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
	target := s.hostTarget(host, password)
	if target.ProxyJump == nil {
		writeError(w, http.StatusBadRequest, "host has no proxy jump configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var actual remote.HostKey
	if s.demo != nil {
		actual, err = s.demo.ProbeJump(ctx, *target.ProxyJump)
	} else {
		actual, err = remote.ProbeJump(ctx, *target.ProxyJump)
	}
	if err != nil {
		s.auditHostActionFailure(r, "trust-jump-key", host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if actual.KeyType != request.KeyType || actual.Fingerprint != request.Fingerprint {
		_ = s.store.AddAudit(s.auditActor(r), "trust-jump-key-failed", "host", host.ID,
			fmt.Sprintf("presented=%s %s approved=%s %s", actual.KeyType, actual.Fingerprint, request.KeyType, request.Fingerprint))
		writeJSON(w, http.StatusConflict, map[string]any{"error": "presented jump host key does not match the approval", "key": actual})
		return
	}
	if err := s.store.SetProxyJumpKeyAs(s.auditActor(r), host.ID, actual.KeyType, actual.Fingerprint); err != nil {
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
var errHostKeyUntrusted = errors.New("host key is not trusted; test and trust the host first")

func looksLikeSudoPasswordInvalid(output string) bool {
	for _, line := range sudoOutputLines(output) {
		for _, needle := range []string{
			"sorry, try again",
			"incorrect password",
			"incorrect password attempt",
			"authentication failure",
			"authentication failed",
		} {
			if strings.Contains(line, needle) {
				return true
			}
		}
	}
	return false
}

func looksLikeSudoAuthFailure(output string) bool {
	for _, line := range sudoOutputLines(output) {
		for _, needle := range []string{
			"interactive authentication is required",
			"a password is required",
			"authentication required but not attempted",
			"authentication failed, try again",
			"no tty present",
			"no askpass program specified",
			"a terminal is required",
			"must have a tty",
		} {
			if strings.Contains(line, needle) {
				return true
			}
		}
	}
	return false
}

// sudoOutputLines returns only lines emitted by sudo itself. Package managers
// can print generic phrases such as "Authentication failed" for repository or
// proxy failures; those must not be mistaken for a sudo password prompt.
func sudoOutputLines(output string) []string {
	lines := make([]string, 0, 4)
	for _, raw := range strings.Split(strings.ToLower(output), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "sudo:") || strings.HasPrefix(line, "[sudo]") {
			lines = append(lines, line)
			continue
		}
		// Some sudo builds print a bare diagnostic when -p '' is used. Accept
		// only exact known diagnostics; package managers can contain similar
		// phrases in longer repository/proxy error lines.
		switch line {
		case "sorry, try again.", "sorry, try again", "incorrect password",
			"authentication failure", "authentication failed":
			lines = append(lines, line)
		}
	}
	return lines
}

func (s *Server) runHelper(ctx context.Context, host store.Host, action, sshPassword, sudoPassword string, timeout time.Duration, args ...string) (string, int, error) {
	return s.runHelperActionInput(ctx, host, action, sshPassword, sudoPassword, "", timeout, args...)
}

func (s *Server) runHelperActionInput(ctx context.Context, host store.Host, action, sshPassword, sudoPassword, input string, timeout time.Duration, args ...string) (string, int, error) {
	switch action {
	case "facts", "preview", "check", "apply", "cleanup-check", "cleanup-apply", "reboot", "reboot-check", "system-info", "metrics", "events", "docker-list", "docker-check", "docker-apply", "docker-update-all",
		"service-restart", "service-enable", "service-disable", "package-remove-preview", "package-remove-apply", "package-install-preview", "package-install-apply", "checkmk-register":
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
		return "", 0, errHostKeyUntrusted
	}
	helperAction := action
	if host.APTUpgradeMode == "full" {
		switch action {
		case "facts", "preview", "check", "apply":
			helperAction = action + "-full"
		}
	}
	if len(args) == 1 {
		helperAction += " " + args[0]
	}
	if s.demo != nil {
		switch action {
		case "service-restart", "service-enable", "service-disable", "package-remove-preview", "package-remove-apply", "package-install-preview", "package-install-apply", "checkmk-register":
			return `{"action":"` + action + `","ok":true,"exit_code":0,"output":"demo: simulated ` + action + `"}`, 0, nil
		}
		// Demo hosts use safe-upgrade simulation; the demo fixture does not
		// install a real helper or depend on the new sudoers actions.
		demoAction := strings.TrimSuffix(helperAction, "-full")
		return s.demo.RunHelper(ctx, host, demoAction, "", timeout)
	}
	command := "sudo -n /usr/local/libexec/hibp/hibp-helper " + helperAction
	if sudoPassword != "" {
		command = "sudo -S -p '' /usr/local/libexec/hibp/hibp-helper " + helperAction
		input = sudoPassword + "\n" + input
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

// auditHostActionFailure records manual privileged failures that happen before
// a helper result is available. Secrets are never included in the detail.
func (s *Server) auditHostActionFailure(r *http.Request, action, hostID string, err error) {
	detail := "unknown failure"
	if err != nil {
		detail = shortRunSummary(err.Error())
	}
	_ = s.store.AddAudit(s.auditActor(r), action+"-failed", "host", hostID, detail)
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
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, "facts", password, request.SudoPassword, 5*time.Minute)
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
	DryRun           bool   `json:"dry_run"`
	Confirm          string `json:"confirm"`
	Password         string `json:"password"`
	SudoPassword     string `json:"sudo_password"`
	RebootAfterPatch bool   `json:"reboot_after_patch"`
	PreviewHash      string `json:"preview_hash"`
	AllowRemovals    bool   `json:"allow_removals"`
}

// patchResponse keeps the existing helper.Result fields and adds the preview,
// refreshed facts, and optional post-patch reboot outcome. Older clients ignore
// the extra fields.
type patchResponse struct {
	helper.Result
	Preview         *helper.PreviewResult `json:"preview,omitempty"`
	PreviewHash     string                `json:"preview_hash,omitempty"`
	NoChanges       bool                  `json:"no_changes,omitempty"`
	Facts           *helper.Facts         `json:"facts,omitempty"`
	FactsError      string                `json:"facts_error,omitempty"`
	RebootRequired  bool                  `json:"reboot_required,omitempty"`
	RebootRequested bool                  `json:"reboot_requested,omitempty"`
	RebootOutput    string                `json:"reboot_output,omitempty"`
	RebootError     string                `json:"reboot_error,omitempty"`
}

type previewResponse struct {
	Preview     helper.PreviewResult `json:"preview"`
	PreviewHash string               `json:"preview_hash"`
}

func previewHash(result helper.PreviewResult) string {
	packages := append([]helper.PackageChange(nil), result.Packages...)
	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Action != packages[j].Action {
			return packages[i].Action < packages[j].Action
		}
		if packages[i].Name != packages[j].Name {
			return packages[i].Name < packages[j].Name
		}
		if packages[i].OldVersion != packages[j].OldVersion {
			return packages[i].OldVersion < packages[j].OldVersion
		}
		if packages[i].NewVersion != packages[j].NewVersion {
			return packages[i].NewVersion < packages[j].NewVersion
		}
		if packages[i].Repository != packages[j].Repository {
			return packages[i].Repository < packages[j].Repository
		}
		return packages[i].Architecture < packages[j].Architecture
	})
	payload, _ := json.Marshal(struct {
		PackageManager string                 `json:"package_manager"`
		Packages       []helper.PackageChange `json:"packages"`
	}{PackageManager: result.PackageManager, Packages: packages})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (s *Server) runPatchPreview(ctx context.Context, host store.Host, password, sudoPassword string) (helper.PreviewResult, string, error) {
	output, code, err := s.runHelper(ctx, host, "preview", password, sudoPassword, 10*time.Minute)
	if err != nil {
		return helper.PreviewResult{}, "", err
	}
	var result helper.PreviewResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return helper.PreviewResult{}, "", fmt.Errorf("helper returned invalid preview JSON: %w", err)
	}
	if code != 0 && result.OK {
		result.OK = false
		if result.Error == "" {
			result.Error = fmt.Sprintf("helper exited with code %d", code)
		}
	}
	if result.Packages == nil {
		result.Packages = []helper.PackageChange{}
	}
	if result.Counts == nil {
		result.Counts = map[string]int{}
	}
	return result, previewHash(result), nil
}

func (s *Server) handlePatchPreview(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request passwordRequest
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
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, cleanup, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	preview, hash, err := s.runPatchPreview(r.Context(), host, password, request.SudoPassword)
	if errors.Is(err, errSudoPasswordInvalid) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, "patch-preview", host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if !preview.OK {
		s.auditHostActionFailure(r, "patch-preview", host.ID, errors.New(preview.Error))
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "patch preview failed", "preview": preview, "preview_hash": hash,
		})
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "patch-preview", "host", host.ID,
		fmt.Sprintf("upgrade=%d install=%d remove=%d exit=%d",
			preview.Counts["upgrade"], preview.Counts["install"], preview.Counts["remove"], preview.ExitCode))
	writeJSON(w, http.StatusOK, previewResponse{Preview: preview, PreviewHash: hash})
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
		if strings.TrimSpace(request.PreviewHash) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "run a patch preview before applying updates", "code": "preview_required",
			})
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

	var preview helper.PreviewResult
	previewHash := ""
	if action == "apply" {
		preview, previewHash, err = s.runPatchPreview(r.Context(), host, password, request.SudoPassword)
		if errors.Is(err, errSudoPasswordInvalid) {
			s.auditHostActionFailure(r, "patch-preview", host.ID, err)
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
			return
		}
		if errors.Is(err, errSudoPasswordRequired) {
			s.auditHostActionFailure(r, "patch-preview", host.ID, err)
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
			return
		}
		if err != nil {
			s.auditHostActionFailure(r, "patch-preview", host.ID, err)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !preview.OK {
			s.auditHostActionFailure(r, "patch-preview", host.ID, errors.New(preview.Error))
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error": "patch preview failed", "preview": preview, "preview_hash": previewHash,
			})
			return
		}
		if previewHash != request.PreviewHash {
			s.auditHostActionFailure(r, "patch-preview", host.ID, errors.New("preview changed before apply"))
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": "the package preview changed; review the new package list before applying",
				"code":  "preview_changed", "preview": preview, "preview_hash": previewHash,
			})
			return
		}
		if preview.Counts["remove"] > 0 && !request.AllowRemovals {
			s.auditHostActionFailure(r, "patch-apply", host.ID, errors.New("package removals were not confirmed"))
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "the preview includes package removals; confirm them before applying",
				"code":  "removals_not_confirmed", "preview": preview, "preview_hash": previewHash,
			})
			return
		}
		if len(preview.Packages) == 0 {
			_ = s.store.AddAudit(s.auditActor(r), "patch-apply-noop", "host", host.ID, "no package changes")
			writeJSON(w, http.StatusOK, patchResponse{
				Result:  helper.Result{Action: "apply", OK: true, ExitCode: 0, Output: "No package changes to apply."},
				Preview: &preview, PreviewHash: previewHash, NoChanges: true,
			})
			return
		}
	}

	output, code, err := s.runHelper(r.Context(), host, action, password, request.SudoPassword, timeout)
	if errors.Is(err, errSudoPasswordInvalid) {
		s.auditHostActionFailure(r, "patch-"+action, host.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		s.auditHostActionFailure(r, "patch-"+action, host.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, "patch-"+action, host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result := parseHelperResult(action, output, code)
	if err := s.store.AddAudit(s.auditActor(r), "patch-"+action, "host", host.ID, fmt.Sprintf("exit=%d", code)); err != nil {
		_ = err
	}
	response := patchResponse{Result: result}
	if action == "apply" {
		response.Preview = &preview
		response.PreviewHash = previewHash
	}
	if action == "apply" && result.OK {
		factsCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
		defer cancel()
		facts, factsErr := s.collectFactsForHost(factsCtx, s.auditActor(r), host, password, request.SudoPassword)
		if factsErr != nil {
			response.FactsError = shortRunSummary(factsErr.Error())
		} else {
			response.Facts = &facts
		}
	}
	// A reboot is only considered after a successful apply run. Dry runs never
	// change a host. The operator opts in per request; existing callers that do
	// not send reboot_after_patch keep the old behavior.
	if action == "apply" && result.OK && request.RebootAfterPatch {
		// The patch already completed. Do not let a closing browser tab cancel
		// the explicit post-patch reboot check, but keep a bounded timeout.
		rebootCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
		defer cancel()
		required, requested, rebootOutput, rebootErr := s.checkAndReboot(rebootCtx, host, password, request.SudoPassword)
		response.RebootRequired = required
		response.RebootRequested = requested
		response.RebootOutput = rebootOutput
		if rebootErr != nil {
			response.RebootError = rebootErr.Error()
			s.auditHostActionFailure(r, "reboot-after-patch", host.ID, rebootErr)
		} else if requested {
			_ = s.store.AddAudit(s.auditActor(r), "reboot", "host", host.ID, "requested after patch")
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func parseHelperResult(action, output string, code int) helper.Result {
	var result helper.Result
	if err := json.Unmarshal([]byte(output), &result); err == nil {
		if result.Action == "" {
			result.Action = action
		}
		if action == "check" && code == 100 {
			result.OK = true
		}
		return result
	}
	return helper.Result{Action: action, OK: code == 0 || (action == "check" && code == 100), ExitCode: code, Output: output}
}

type cleanupRequest struct {
	DryRun          bool   `json:"dry_run"`
	Confirm         string `json:"confirm"`
	Password        string `json:"password"`
	SudoPassword    string `json:"sudo_password"`
	AllowController bool   `json:"allow_controller"`
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	host, err := s.store.GetHost(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	var request cleanupRequest
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
	action := "cleanup-check"
	timeout := 5 * time.Minute
	if !request.DryRun {
		if request.Confirm != "cleanup" {
			writeError(w, http.StatusBadRequest, "confirm must be \"cleanup\" for a real package cleanup")
			return
		}
		if s.isControllerHost(host) && !request.AllowController {
			s.auditHostActionFailure(r, "cleanup", host.ID, errors.New("controller cleanup requires explicit per-host approval"))
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "refusing to clean up the HIBP controller from a batch or API request without explicit per-host approval",
				"code":  "controller_protected",
			})
			return
		}
		action = "cleanup-apply"
		timeout = 30 * time.Minute
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, cleanup, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, action, password, request.SudoPassword, timeout)
	if errors.Is(err, errSudoPasswordInvalid) {
		s.auditHostActionFailure(r, action, host.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		s.auditHostActionFailure(r, action, host.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, action, host.ID, err)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	var result helper.CleanupResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper returned invalid JSON", "output": output})
		return
	}
	if code != 0 && result.OK {
		result.OK = false
		if result.Error == "" {
			result.Error = fmt.Sprintf("helper exited with code %d", code)
		}
	}
	if action == "cleanup-apply" && result.OK {
		_ = s.store.UpdateOrphanedPackages(host.ID, result.Remaining)
	}
	detail := ""
	if action == "cleanup-apply" {
		detail = fmt.Sprintf("removed=%d remaining=%d", result.Count, result.Remaining)
	} else {
		detail = fmt.Sprintf("orphaned=%d exit=%d", result.Count, code)
	}
	_ = s.store.AddAudit(s.auditActor(r), action, "host", host.ID, detail)
	writeJSON(w, http.StatusOK, result)
}

// checkAndReboot asks the fixed helper whether the target needs a reboot after
// a successful patch and, when it does, requests that reboot through the same
// restricted helper action. It never uses a shell or an arbitrary command.
func (s *Server) checkAndReboot(ctx context.Context, host store.Host, sshPassword, sudoPassword string) (bool, bool, string, error) {
	if s.isControllerHost(host) {
		return false, false, "", errors.New("refusing to reboot the HIBP controller automatically; use the per-host Reboot button")
	}
	checkOutput, checkCode, err := s.runHelper(ctx, host, "reboot-check", sshPassword, sudoPassword, 2*time.Minute)
	if err != nil {
		return false, false, checkOutput, fmt.Errorf("reboot check failed: %w", err)
	}
	if checkCode != 0 {
		return false, false, checkOutput, fmt.Errorf("reboot check exited with code %d", checkCode)
	}
	required, err := rebootRequiredFromHelperOutput(checkOutput)
	if err != nil {
		return false, false, checkOutput, err
	}
	if !required {
		return false, false, "no reboot required", nil
	}
	rebootOutput, rebootCode, err := s.runHelper(ctx, host, "reboot", sshPassword, sudoPassword, 2*time.Minute)
	if err != nil {
		return true, false, rebootOutput, fmt.Errorf("reboot failed: %w", err)
	}
	if rebootCode != 0 {
		return true, false, rebootOutput, fmt.Errorf("reboot exited with code %d", rebootCode)
	}
	_ = s.store.SetHostStatus(host.ID, "unknown")
	return true, true, rebootOutput, nil
}

// rebootRequiredFromHelperOutput parses the JSON contract returned by the
// helper's reboot-check action. Anything unexpected is treated as an error so
// an automatic reboot is never requested from ambiguous output.
func rebootRequiredFromHelperOutput(output string) (bool, error) {
	var result helper.Result
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return false, fmt.Errorf("invalid reboot-check output: %w", err)
	}
	if !result.OK {
		if result.Error != "" {
			return false, fmt.Errorf("reboot check failed: %s", result.Error)
		}
		return false, errors.New("reboot check failed")
	}
	switch strings.TrimSpace(result.Output) {
	case "reboot required":
		return true, nil
	case "no reboot required":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected reboot-check output %q", strings.TrimSpace(result.Output))
	}
}

type rebootRequest struct {
	Confirm         string `json:"confirm"`
	Password        string `json:"password"`
	SudoPassword    string `json:"sudo_password"`
	AllowController bool   `json:"allow_controller"`
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
	if s.isControllerHost(host) && !request.AllowController {
		s.auditHostActionFailure(r, "reboot", host.ID, errors.New("controller reboot requires explicit per-host approval"))
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "refusing to reboot the HIBP controller from a batch or API request without explicit per-host approval",
			"code":  "controller_protected",
		})
		return
	}
	if !s.tryLockHost(host.ID) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
		return
	}
	defer s.unlockHost(host.ID)
	output, code, err := s.runHelper(r.Context(), host, "reboot", password, request.SudoPassword, 2*time.Minute)
	if errors.Is(err, errSudoPasswordInvalid) {
		s.auditHostActionFailure(r, "reboot", host.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, errSudoPasswordRequired) {
		s.auditHostActionFailure(r, "reboot", host.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, "reboot", host.ID, err)
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

func (s *Server) collectFactsForHost(ctx context.Context, actor string, host store.Host, password, sudoPassword string) (helper.Facts, error) {
	output, code, err := s.runHelper(ctx, host, "facts", password, sudoPassword, 5*time.Minute)
	if err != nil {
		return helper.Facts{}, err
	}
	if code != 0 {
		return helper.Facts{}, fmt.Errorf("facts helper exited with code %d", code)
	}
	var facts helper.Facts
	if err := json.Unmarshal([]byte(output), &facts); err != nil {
		return helper.Facts{}, fmt.Errorf("helper returned invalid facts JSON: %w", err)
	}
	if err := s.store.SaveFactsAs(actor, host.ID, storeFactsFromHelper(facts)); err != nil {
		return helper.Facts{}, err
	}
	return facts, nil
}

func storeFactsFromHelper(facts helper.Facts) store.Facts {
	return store.Facts{
		CollectedAt:         crypto.Now(),
		UptimeSeconds:       facts.UptimeSeconds,
		BootTime:            facts.BootTime,
		Kernel:              facts.Kernel,
		OSPrettyName:        facts.OSPrettyName,
		PackageManager:      facts.PackageManager,
		RebootRequired:      facts.RebootRequired,
		DiskFreeBytes:       facts.DiskFreeBytes,
		TimeSyncOK:          facts.TimeSyncOK,
		TimeSyncSource:      facts.TimeSyncSource,
		TimeSyncOffset:      facts.TimeSyncOffset,
		TimeSyncOffsetKnown: facts.TimeSyncOffsetKnown,
		TimeSyncStratum:     facts.TimeSyncStratum,
		TimeSyncLastSync:    facts.TimeSyncLastSync,
		PendingUpdates:      facts.PendingUpdates,
		OrphanedPackages:    facts.OrphanedPackages,
		CleanupSupported:    facts.CleanupSupported,
		Agent:               facts.Agent,
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
	if s.demo != nil {
		if !s.tryLockHost(host.ID) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "another patch, reboot, or bootstrap operation is already running for this host", "code": "host_busy"})
			return
		}
		defer s.unlockHost(host.ID)
		output, err := s.demo.InstallHelper(r.Context(), host, nil, request.SudoPassword)
		if err != nil {
			s.auditHostActionFailure(r, "bootstrap-helper", host.ID, err)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		var facts helper.Facts
		if json.Unmarshal([]byte(output), &facts) == nil {
			_ = s.store.SaveFactsAs(s.auditActor(r), host.ID, storeFactsFromHelper(facts))
		}
		_ = s.store.AddAudit(s.auditActor(r), "bootstrap-helper", "host", host.ID, "demo: installed restricted helper")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": output})
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
		s.auditHostActionFailure(r, "bootstrap-helper", host.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "sudo_password_invalid"})
		return
	}
	if errors.Is(err, remote.ErrSudoPasswordRequired) {
		s.auditHostActionFailure(r, "bootstrap-helper", host.ID, err)
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "sudo_password_required"})
		return
	}
	if err != nil {
		s.auditHostActionFailure(r, "bootstrap-helper", host.ID, err)
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
	_ = writer.Write([]string{"name", "address", "port", "username", "auth_type", "os", "status", "pending_updates", "orphaned_packages", "cleanup_supported", "reboot_required", "uptime_seconds", "last_check", "tags", "group", "cmdb_ci_id"})
	for _, host := range hosts {
		pending, orphaned, cleanupSupported, reboot, uptime, last := "", "", "", "", "", ""
		if host.Facts != nil {
			pending = strconv.Itoa(host.Facts.PendingUpdates)
			orphaned = strconv.Itoa(host.Facts.OrphanedPackages)
			cleanupSupported = strconv.FormatBool(host.Facts.CleanupSupported)
			reboot = strconv.FormatBool(host.Facts.RebootRequired)
			uptime = strconv.FormatInt(host.Facts.UptimeSeconds, 10)
			last = host.Facts.CollectedAt
		}
		_ = writer.Write([]string{
			neutralizeCSV(host.Name), neutralizeCSV(host.Address), strconv.Itoa(host.Port),
			neutralizeCSV(host.Username), host.AuthType, neutralizeCSV(host.OSFamily + " " + host.OSVersion),
			host.Status, pending, orphaned, cleanupSupported, reboot, uptime, last, neutralizeCSV(host.Tags),
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
	if s.demo != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "path": "/demo/backups/hibp-demo.bac",
			"sidecar": "/demo/backups/hibp-demo.bac.meta", "demo": true,
		})
		return
	}
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
	if s.demo != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "path": "/demo/restore/hibp-demo.db",
			"sidecar": "/demo/restore/hibp-demo.db.meta", "demo": true,
		})
		return
	}
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
