// Command hibp is the HIBP server and target helper.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/server"
	"github.com/RogerBergling/hibp/internal/store"
	"golang.org/x/term"
)

var version = "0.1.0-dev"

func main() {
	// SQLite creates -wal and -shm files; keep every file created by HIBP
	// owner-only even if the service manager uses a permissive umask.
	syscall.Umask(0o077)
	args := normalizeArgs(os.Args)
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "server":
		err = runServer(args[1:])
	case "helper":
		err = runHelper(args[1:])
	case "user":
		err = runUser(args[1:])
	case "version", "--version", "-version":
		fmt.Println("hibp " + version)
		fmt.Println("sqlcipher driver:", store.DriverName)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// normalizeArgs lets the same binary run as /usr/local/libexec/hibp/hibp-helper
// with the action as the first argument, while preserving "hibp helper <action>"
// for the normal binary name and the preflight .hibp-helper.<suffix> candidate.
func normalizeArgs(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	args := argv[1:]
	if filepath.Base(argv[0]) != "hibp-helper" {
		return args
	}
	if len(args) > 0 {
		switch args[0] {
		case "helper", "version", "--version", "-version", "help", "--help", "-h":
			return args
		}
	}
	return append([]string{"helper"}, args...)
}

func usage() {
	fmt.Fprintln(os.Stderr, `HIBP - Have I Been Patched

Usage:
  hibp server [flags]     Run the local browser UI and API
  hibp helper <action>    Run a fixed target action (facts|check|apply|reboot|reboot-check|system-info|metrics|docker-list)
  hibp user reset         Reset the local account password, TOTP, and passkeys
  hibp version            Print the version

Server flags:
  -db string              Database path (default: XDG data directory)
  -listen string          Listen address (default: 127.0.0.1:8443)
  -create                 Create the database if it does not exist
  -passphrase-file string Read the database passphrase from a 0600 file
  -key-dir string         SSH key directory, comma-separated (default: ~/.ssh)
  -ssh-config string      OpenSSH client config (default: ~/.ssh/config)
  -demo                   Seed sample hosts when the database is empty
  -version                Print the version`)
}

func defaultKeyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

func splitList(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func defaultDBPath() string {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "hibp", "hibp.db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "hibp.db"
	}
	return filepath.Join(home, ".local", "share", "hibp", "hibp.db")
}

func readPassphrase(path string) ([]byte, error) {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("passphrase file %s must not be accessible by group or others", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimRight(string(data), "\r\n")), nil
	}
	fmt.Fprint(os.Stderr, "Database passphrase: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pass, nil
}

func runServer(args []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	dbPath := flags.String("db", defaultDBPath(), "database path")
	listen := flags.String("listen", "127.0.0.1:8443", "listen address")
	create := flags.Bool("create", false, "create the database if it does not exist")
	passphraseFile := flags.String("passphrase-file", "", "read passphrase from a 0600 file")
	keyDir := flags.String("key-dir", defaultKeyDir(), "SSH key directory, comma-separated for multiple")
	sshConfig := flags.String("ssh-config", filepath.Join(defaultKeyDir(), "config"), "local OpenSSH client config")
	demo := flags.Bool("demo", false, "seed sample hosts when empty")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("hibp " + version)
		return nil
	}
	if *listen != "127.0.0.1:8443" && !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "localhost:") {
		return fmt.Errorf("refusing to listen on %q: use 127.0.0.1 or localhost; use an SSH tunnel for remote access", *listen)
	}

	passphrase, err := readPassphrase(*passphraseFile)
	if err != nil {
		return err
	}
	defer crypto.Zero(passphrase)
	if len(passphrase) < 12 {
		return fmt.Errorf("passphrase must be at least 12 characters")
	}

	opts := store.DefaultOptions()
	opts.Create = *create
	db, err := store.Open(*dbPath, passphrase, opts)
	if err != nil {
		return err
	}
	defer db.Close()

	if *demo {
		if err := seedDemo(db); err != nil {
			return err
		}
	}

	app, err := server.New(server.Config{
		Store:         db,
		Version:       version,
		KeyDirs:       splitList(*keyDir),
		SSHConfigPath: *sshConfig,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return err
	}
	url := "http://localhost:" + port + "/"
	fmt.Fprintf(os.Stderr, "HIBP %s\n", version)
	fmt.Fprintf(os.Stderr, "SQLCipher: %s\n", store.DriverName)
	if !store.ProductionDriver {
		fmt.Fprintln(os.Stderr, "WARNING: this is the M1 spike driver. Build with `make production` before deployment.")
	}
	fmt.Fprintf(os.Stderr, "Database: %s\n", db.Path())
	fmt.Fprintf(os.Stderr, "Open:     %s\n", url)
	fmt.Fprintln(os.Stderr, "Auth:     password + TOTP/passkey (create the account on first visit)")
	fmt.Fprintln(os.Stderr, "Press Ctrl+C to stop.")

	httpServer := &http.Server{
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go app.RunCollector(ctx)
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.Serve(listener) }()
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}

func runHelper(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: hibp helper <facts|check|apply|reboot|reboot-check|system-info|metrics|docker-list>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	return helper.Run(ctx, args[0], os.Stdout)
}

func runUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: hibp user reset --username <name>")
	}
	switch args[0] {
	case "reset":
		return runUserReset(args[1:])
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
}

func runUserReset(args []string) error {
	flags := flag.NewFlagSet("user reset", flag.ContinueOnError)
	dbPath := flags.String("db", defaultDBPath(), "database path")
	passphraseFile := flags.String("passphrase-file", "", "read database passphrase from a 0600 file")
	username := flags.String("username", "", "username to reset")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*username) == "" {
		return errors.New("--username is required")
	}
	passphrase, err := readPassphrase(*passphraseFile)
	if err != nil {
		return err
	}
	defer crypto.Zero(passphrase)
	db, err := store.Open(*dbPath, passphrase, store.DefaultOptions())
	if err != nil {
		return err
	}
	defer db.Close()
	user, err := db.GetUserByUsername(*username)
	if err != nil {
		return fmt.Errorf("user %q: %w", *username, err)
	}
	password, err := readNewPassword("New password: ")
	if err != nil {
		return err
	}
	defer crypto.Zero(password)
	if err := auth.ValidatePassword(string(password)); err != nil {
		return err
	}
	confirm, err := readNewPassword("Confirm password: ")
	if err != nil {
		return err
	}
	defer crypto.Zero(confirm)
	if subtle.ConstantTimeCompare(password, confirm) != 1 {
		return errors.New("passwords do not match")
	}
	hash, err := auth.HashPassword(string(password))
	if err != nil {
		return err
	}
	if err := db.ResetUserAuth(user.ID, hash); err != nil {
		return err
	}
	_ = db.AddAudit("cli", "reset-auth", "user", user.ID, "password, TOTP, passkeys, and sessions reset")
	fmt.Printf("Reset password and MFA for %s.\n", user.Username)
	return nil
}

func readNewPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return password, nil
}

func seedDemo(db *store.Store) error {
	count, err := db.CountHosts()
	if err != nil || count > 0 {
		return err
	}
	samples := []struct {
		host  store.Host
		facts store.Facts
	}{
		{store.Host{Name: "web01", Address: "10.20.0.11", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "web,prod", GroupName: "web-prod", Status: "reachable"}, store.Facts{UptimeSeconds: 41 * 86400, Kernel: "6.8.0-51", OSPrettyName: "Ubuntu 24.04 LTS", PackageManager: "apt", PendingUpdates: 4, RebootRequired: true, DiskFreeBytes: 42 << 30, TimeSyncOK: true}},
		{store.Host{Name: "db01", Address: "10.20.0.21", Port: 22, Username: "root", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "db,prod", GroupName: "db-prod", Status: "reachable"}, store.Facts{UptimeSeconds: 112 * 86400, Kernel: "6.1.0-34", OSPrettyName: "Debian 12", PackageManager: "apt", PendingUpdates: 0, DiskFreeBytes: 80 << 30, TimeSyncOK: true}},
		{store.Host{Name: "fedora01", Address: "10.20.0.31", Port: 22, Username: "fedora", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "web,prod", GroupName: "web-prod", Status: "reachable"}, store.Facts{UptimeSeconds: 12 * 86400, Kernel: "6.12.4", OSPrettyName: "Fedora 41", PackageManager: "dnf", PendingUpdates: 7, RebootRequired: true, DiskFreeBytes: 35 << 30, TimeSyncOK: true}},
		{store.Host{Name: "kali-lab", Address: "10.20.0.41", Port: 22, Username: "kali", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "lab", GroupName: "lab", Status: "reachable"}, store.Facts{UptimeSeconds: 3 * 86400, Kernel: "6.12.9", OSPrettyName: "Kali GNU/Linux 2026.1", PackageManager: "apt", PendingUpdates: 2, DiskFreeBytes: 18 << 30, TimeSyncOK: false}},
		{store.Host{Name: "suse01", Address: "10.20.0.51", Port: 22, Username: "root", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "db,prod", GroupName: "db-prod", Status: "reachable"}, store.Facts{UptimeSeconds: 27 * 86400, Kernel: "6.4.0", OSPrettyName: "openSUSE Leap 15.6", PackageManager: "zypper", PendingUpdates: 1, DiskFreeBytes: 60 << 30, TimeSyncOK: true}},
		{store.Host{Name: "arch01", Address: "10.20.0.61", Port: 22, Username: "roger", AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519", Tags: "lab", GroupName: "lab", Status: "reachable"}, store.Facts{UptimeSeconds: 8 * 86400, Kernel: "6.13.1", OSPrettyName: "Arch Linux", PackageManager: "pacman", PendingUpdates: 0, DiskFreeBytes: 25 << 30, TimeSyncOK: true}},
	}
	for _, sample := range samples {
		host, err := db.CreateHost(sample.host)
		if err != nil {
			return err
		}
		sample.facts.CollectedAt = crypto.Now()
		sample.facts.BootTime = time.Now().UTC().Add(-time.Duration(sample.facts.UptimeSeconds) * time.Second).Format(time.RFC3339)
		if err := db.SaveFacts(host.ID, sample.facts); err != nil {
			return err
		}
	}
	slog.Info("seeded demo hosts", "count", len(samples))
	return nil
}
