//go:build demo

// Command hibp-demo runs the public, fake-data demonstration server. It is
// intentionally a separate binary and image from the production controller.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/server"
	"github.com/RogerBergling/hibp/internal/store"
)

var (
	version     = "demo"
	buildNumber = "demo"
	buildCommit = "unknown"
	buildDate   = "unknown"
	buildTarget = "linux/amd64"
	buildType   = "demo"
)

const demoPassphrase = "hibp-demo-passphrase-not-a-secret"

func main() {
	syscall.Umask(0o077)
	buildinfo.Current = buildinfo.Info{
		Version: version, BuildNumber: buildNumber, BuildCommit: buildCommit,
		BuildDate: buildDate, BuildTarget: buildTarget, BuildType: buildType,
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "hibp-demo-*")
	if err != nil {
		return fmt.Errorf("create demo directory: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure demo directory: %w", err)
	}
	keyDir := "/tmp/hibp-demo-ssh"
	_ = os.RemoveAll(keyDir)
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return fmt.Errorf("create demo SSH directory: %w", err)
	}
	defer os.RemoveAll(keyDir)
	if err := os.WriteFile(filepath.Join(keyDir, "id_ed25519"), []byte("demo-only-not-a-real-private-key\n"), 0o600); err != nil {
		return fmt.Errorf("write demo key: %w", err)
	}
	sshConfig := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(sshConfig, []byte(`Host demo-web01
  HostName 10.20.0.11
  User ubuntu
  IdentityFile /tmp/hibp-demo-ssh/id_ed25519

Host demo-db01
  HostName 10.20.0.21
  User root
  IdentityFile /tmp/hibp-demo-ssh/id_ed25519
`), 0o600); err != nil {
		return fmt.Errorf("write demo SSH config: %w", err)
	}

	db, err := store.Open(filepath.Join(dir, "hibp.db"), []byte(demoPassphrase), store.Options{Create: true})
	if err != nil {
		return fmt.Errorf("create demo database: %w", err)
	}
	defer db.Close()
	if err := server.SeedDemo(db); err != nil {
		return fmt.Errorf("seed demo data: %w", err)
	}

	listen := strings.TrimSpace(os.Getenv("HIBP_DEMO_LISTEN"))
	if listen == "" {
		if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
			listen = "0.0.0.0:" + port
		} else {
			listen = "0.0.0.0:8080"
		}
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid HIBP_DEMO_LISTEN %q: %w", listen, err)
	}
	publicURL := strings.TrimSpace(os.Getenv("HIBP_DEMO_PUBLIC_URL"))
	if publicURL == "" {
		publicURL = "http://localhost:" + listenPort
	}
	allowInsecureHTTP := false
	if raw := strings.TrimSpace(os.Getenv("HIBP_DEMO_ALLOW_INSECURE_HTTP")); raw != "" {
		allowInsecureHTTP, err = strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid HIBP_DEMO_ALLOW_INSECURE_HTTP %q: %w", raw, err)
		}
	}
	app, err := server.New(server.Config{
		Store:             db,
		Version:           version,
		Build:             buildinfo.Current,
		KeyDirs:           []string{keyDir},
		SSHConfigPath:     sshConfig,
		PublicURL:         publicURL,
		Demo:              true,
		AllowInsecureHTTP: allowInsecureHTTP,
		TrustProxy:        strings.HasPrefix(strings.ToLower(publicURL), "https://"),
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	httpServer := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go app.RunCollector(ctx)
	go app.RunMonitor(ctx)
	go app.RunJobs(ctx)
	go app.RunScheduler(ctx)

	fmt.Fprintf(os.Stderr, "HIBP demo %s\n", buildinfo.Current.String())
	fmt.Fprintf(os.Stderr, "Listen:   %s (plain HTTP)\n", listen)
	fmt.Fprintf(os.Stderr, "Public:   %s\n", strings.TrimSuffix(publicURL, "/")+"/")
	if strings.HasPrefix(strings.ToLower(publicURL), "https://") {
		fmt.Fprintln(os.Stderr, "          HTTPS must be terminated by a reverse proxy; the demo itself serves HTTP")
	}
	fmt.Fprintf(os.Stderr, "Login:    %s / %s + TOTP shown on the sign-in page\n", "guest", "guest")
	fmt.Fprintln(os.Stderr, "Mode:     fake data, simulated SSH/email/network/package actions")
	fmt.Fprintln(os.Stderr, "Reset:    restart the container; the demo database is ephemeral")
	if allowInsecureHTTP && strings.HasPrefix(strings.ToLower(publicURL), "http://") {
		fmt.Fprintln(os.Stderr, "WARNING:  insecure HTTP allowed; use this on a trusted LAN only")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	slog.Info("demo stopped")
	return nil
}
