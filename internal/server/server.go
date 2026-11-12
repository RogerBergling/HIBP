// Package server exposes the local browser UI and JSON API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/RogerBergling/hibp/internal/webui"
)

// dummyPasswordHash is computed once so a missing username still pays the
// Argon2 cost during login, without rebuilding the hash for every test server.
var dummyPasswordHash = auth.DummyPasswordHash()

// Config configures the local server.
type Config struct {
	Store         *store.Store
	Version       string
	Build         buildinfo.Info
	KeyDirs       []string
	SSHConfigPath string
}

// Server is the HIBP HTTP server.
type Server struct {
	store              *store.Store
	build              buildinfo.Info
	keyDirs            []string
	sshConfigPath      string
	dummyPasswordHash  string
	loginIPLimiter     *attemptLimiter
	loginUserLimiter   *attemptLimiter
	mfaLimiter         *attemptLimiter
	ceremonies         *ceremonyStore
	setupMu            sync.Mutex
	collectorMu        sync.Mutex
	collectorState     map[string]*collectorHostState
	mailMu             sync.Mutex
	monitorMu          sync.Mutex
	monitorRunning     bool
	monitorWake        chan struct{}
	integrationMu      sync.Mutex
	integrationRunning bool
	integrationWake    chan struct{}
	integrationRuntime map[string]integrationRuntime
	schedulerMu        sync.Mutex
	schedulerScanning  bool
	schedulerRunning   map[string]bool
	schedulerCtx       context.Context
	schedulerWake      chan struct{}
	schedulerSlots     chan struct{}
	hostLocksMu        sync.Mutex
	hostLocks          map[string]bool
	mux                *http.ServeMux
}

// New creates a server.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("store is required")
	}
	if len(cfg.KeyDirs) == 0 {
		home, err := os.UserHomeDir()
		if err == nil {
			cfg.KeyDirs = []string{filepath.Join(home, ".ssh")}
		}
	}
	keyDirs := make([]string, 0, len(cfg.KeyDirs))
	for _, dir := range cfg.KeyDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		keyDirs = append(keyDirs, abs)
	}
	sshConfigPath, err := resolveHomePath(cfg.SSHConfigPath)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SSHConfigPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		sshConfigPath = filepath.Join(home, ".ssh", "config")
	}
	build := cfg.Build
	if strings.TrimSpace(build.Version) == "" {
		build.Version = cfg.Version
	}
	if strings.TrimSpace(build.Version) == "" {
		build.Version = "dev"
	}
	s := &Server{
		store:              cfg.Store,
		build:              build,
		keyDirs:            keyDirs,
		sshConfigPath:      sshConfigPath,
		dummyPasswordHash:  dummyPasswordHash,
		loginIPLimiter:     newAttemptLimiter(10, 15*time.Minute),
		loginUserLimiter:   newAttemptLimiter(5, 15*time.Minute),
		mfaLimiter:         newAttemptLimiter(10, 15*time.Minute),
		ceremonies:         newCeremonyStore(),
		collectorState:     make(map[string]*collectorHostState),
		monitorWake:        make(chan struct{}, 1),
		integrationWake:    make(chan struct{}, 1),
		integrationRuntime: make(map[string]integrationRuntime),
		schedulerRunning:   make(map[string]bool),
		schedulerWake:      make(chan struct{}, 1),
		schedulerSlots:     make(chan struct{}, 20),
		hostLocks:          make(map[string]bool),
		mux:                http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /app.js", s.handleAsset("app.js", "application/javascript; charset=utf-8"))
	s.mux.HandleFunc("GET /style.css", s.handleAsset("style.css", "text/css; charset=utf-8"))
	s.mux.HandleFunc("GET /favicon.svg", s.handleAsset("favicon.svg", "image/svg+xml"))

	s.mux.HandleFunc("GET /api/v1/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/v1/auth/setup", s.handleSetup)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.authPending(s.handleLogout))
	s.mux.HandleFunc("GET /api/v1/auth/me", s.authPending(s.handleMe))
	s.mux.HandleFunc("POST /api/v1/auth/totp/begin", s.authPending(s.handleTOTPBegin))
	s.mux.HandleFunc("POST /api/v1/auth/totp/verify", s.authPending(s.handleTOTPVerify))
	s.mux.HandleFunc("POST /api/v1/auth/passkey/register/begin", s.authPending(s.handlePasskeyRegisterBegin))
	s.mux.HandleFunc("POST /api/v1/auth/passkey/register/finish", s.authPending(s.handlePasskeyRegisterFinish))
	s.mux.HandleFunc("POST /api/v1/auth/passkey/login/begin", s.authPending(s.handlePasskeyLoginBegin))
	s.mux.HandleFunc("POST /api/v1/auth/passkey/login/finish", s.authPending(s.handlePasskeyLoginFinish))
	s.mux.HandleFunc("GET /api/v1/auth/mfa", s.auth(s.handleMFAStatus))
	s.mux.HandleFunc("DELETE /api/v1/auth/passkeys/{id}", s.auth(s.handleDeletePasskey))
	s.mux.HandleFunc("DELETE /api/v1/auth/totp", s.auth(s.handleDeleteTOTP))

	s.mux.HandleFunc("GET /api/v1/status", s.auth(s.handleStatus))
	s.mux.HandleFunc("GET /api/v1/hosts", s.auth(s.handleListHosts))
	s.mux.HandleFunc("POST /api/v1/hosts", s.auth(s.handleCreateHost))
	s.mux.HandleFunc("GET /api/v1/hosts/{id}", s.auth(s.handleGetHost))
	s.mux.HandleFunc("PUT /api/v1/hosts/{id}", s.auth(s.handleUpdateHost))
	s.mux.HandleFunc("DELETE /api/v1/hosts/{id}", s.auth(s.handleDeleteHost))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/test", s.auth(s.handleTestHost))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/trust-key", s.auth(s.handleTrustKey))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/facts", s.auth(s.handleFacts))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/bootstrap", s.auth(s.handleBootstrap))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/patch", s.auth(s.handlePatch))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/reboot", s.auth(s.handleReboot))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/system-info", s.auth(s.handleSystemInfo))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/list", s.auth(s.handleDockerList))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/check", s.auth(s.handleDockerCheck))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/check-all", s.auth(s.handleDockerCheckAll))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/apply", s.auth(s.handleDockerApply))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/update-all", s.auth(s.handleDockerUpdateAll))
	s.mux.HandleFunc("POST /api/v1/hosts/{id}/docker/update-selected", s.auth(s.handleDockerUpdateSelected))
	s.mux.HandleFunc("GET /api/v1/hosts/{id}/details", s.auth(s.handleHostDetails))
	s.mux.HandleFunc("GET /api/v1/settings", s.auth(s.handleGetSettings))
	s.mux.HandleFunc("PUT /api/v1/settings", s.auth(s.handlePutSettings))
	s.mux.HandleFunc("GET /api/v1/notifications/smtp", s.auth(s.handleGetSMTP))
	s.mux.HandleFunc("PUT /api/v1/notifications/smtp", s.auth(s.handlePutSMTP))
	s.mux.HandleFunc("POST /api/v1/notifications/smtp/test", s.auth(s.handleTestSMTP))
	s.mux.HandleFunc("GET /api/v1/monitors", s.auth(s.handleListMonitors))
	s.mux.HandleFunc("POST /api/v1/monitors", s.auth(s.handleCreateMonitor))
	s.mux.HandleFunc("PUT /api/v1/monitors/{id}", s.auth(s.handleUpdateMonitor))
	s.mux.HandleFunc("DELETE /api/v1/monitors/{id}", s.auth(s.handleDeleteMonitor))
	s.mux.HandleFunc("POST /api/v1/monitors/{id}/check", s.auth(s.handleCheckMonitor))
	s.mux.HandleFunc("GET /api/v1/alerts", s.auth(s.handleAlerts))
	s.mux.HandleFunc("GET /api/v1/integrations", s.auth(s.handleListIntegrations))
	s.mux.HandleFunc("GET /api/v1/integrations/{source}", s.auth(s.handleGetIntegration))
	s.mux.HandleFunc("PUT /api/v1/integrations/{source}", s.auth(s.handlePutIntegration))
	s.mux.HandleFunc("POST /api/v1/integrations/{source}/test", s.auth(s.handleTestIntegration))
	s.mux.HandleFunc("POST /api/v1/integrations/{source}/check", s.auth(s.handleCheckIntegration))
	s.mux.HandleFunc("GET /api/v1/schedules", s.auth(s.handleListSchedules))
	s.mux.HandleFunc("POST /api/v1/schedules", s.auth(s.handleCreateSchedule))
	s.mux.HandleFunc("PUT /api/v1/schedules/{id}", s.auth(s.handleUpdateSchedule))
	s.mux.HandleFunc("DELETE /api/v1/schedules/{id}", s.auth(s.handleDeleteSchedule))
	s.mux.HandleFunc("POST /api/v1/schedules/{id}/run", s.auth(s.handleRunSchedule))
	s.mux.HandleFunc("GET /api/v1/runs", s.auth(s.handleListRuns))
	s.mux.HandleFunc("POST /api/v1/import", s.auth(s.handleImport))
	s.mux.HandleFunc("POST /api/v1/cmdb/import", s.auth(s.handleCMDBImport))
	s.mux.HandleFunc("GET /api/v1/audit", s.auth(s.handleAudit))
	s.mux.HandleFunc("GET /api/v1/audit/verify", s.auth(s.handleAuditVerify))
	s.mux.HandleFunc("GET /api/v1/export/hosts.csv", s.auth(s.handleExportHosts))
	s.mux.HandleFunc("POST /api/v1/backup", s.auth(s.handleBackup))
	s.mux.HandleFunc("POST /api/v1/restore", s.auth(s.handleRestore))
	s.mux.HandleFunc("GET /api/v1/keys", s.auth(s.handleListKeys))
	s.mux.HandleFunc("GET /api/v1/ssh/config", s.auth(s.handleSSHConfig))
}

// Handler returns the middleware-wrapped handler.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.hostCheck(s.mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		host = strings.Trim(host, "[]")
		switch host {
		case "127.0.0.1", "localhost", "::1":
		default:
			writeError(w, http.StatusForbidden, "unexpected Host header")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Host != r.Host {
				writeError(w, http.StatusForbidden, "unexpected Origin header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.serveAsset(w, "index.html", "text/html; charset=utf-8")
}

func (s *Server) handleAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.serveAsset(w, name, contentType)
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := fs.ReadFile(webui.FS, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func resolveHomePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	return filepath.Abs(path)
}

func (s *Server) hostTarget(host store.Host, password string) remote.Target {
	return remote.Target{Address: host.Address, Port: host.Port, Username: host.Username, KeyPath: host.KeyPath, Password: password}
}
