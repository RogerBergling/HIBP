// Package helper implements the fixed, root-owned actions executed on targets.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RogerBergling/hibp/internal/buildinfo"
)

const maxOutput = 1 << 20 // 1 MiB

// Facts is the JSON contract returned by the facts action.
type Facts struct {
	OSID           string         `json:"os_id"`
	OSVersion      string         `json:"os_version"`
	OSPrettyName   string         `json:"os_pretty_name"`
	Kernel         string         `json:"kernel"`
	PackageManager string         `json:"package_manager"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
	BootTime       string         `json:"boot_time"`
	PendingUpdates int            `json:"pending_updates"`
	RebootRequired bool           `json:"reboot_required"`
	DiskFreeBytes  int64          `json:"disk_free_bytes"`
	TimeSyncOK     bool           `json:"time_sync_ok"`
	Agent          buildinfo.Info `json:"agent"`
}

// Result is the JSON contract for check/apply/reboot/reboot-check.
type Result struct {
	Action   string `json:"action"`
	OK       bool   `json:"ok"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

// Runner executes a fixed command.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, int, error)

var commandRunner Runner = defaultRunner

// lookPath resolves a fixed binary name to an absolute path. The helper runs
// as root through sudo, so it must not depend on an inherited PATH.
var lookPath = func(name string) (string, error) {
	candidates := map[string][]string{
		"apt-get":          {"/usr/bin/apt-get", "/bin/apt-get"},
		"dnf":              {"/usr/bin/dnf", "/bin/dnf"},
		"zypper":           {"/usr/bin/zypper", "/sbin/zypper"},
		"pacman":           {"/usr/bin/pacman", "/bin/pacman"},
		"apk":              {"/sbin/apk", "/usr/sbin/apk", "/usr/bin/apk"},
		"needs-restarting": {"/usr/bin/needs-restarting", "/bin/needs-restarting"},
		"timedatectl":      {"/usr/bin/timedatectl", "/bin/timedatectl"},
		"systemctl":        {"/usr/bin/systemctl", "/bin/systemctl"},
		"shutdown":         {"/usr/sbin/shutdown", "/sbin/shutdown", "/usr/bin/shutdown", "/bin/shutdown"},
		"docker":           {"/usr/bin/docker", "/usr/local/bin/docker", "/bin/docker"},
		"ss":               {"/usr/bin/ss", "/bin/ss", "/usr/sbin/ss", "/sbin/ss"},
	}
	for _, path := range candidates[name] {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", exec.ErrNotFound
}

// SetRunnerForTest replaces the command runner and returns a restore function.
func SetRunnerForTest(r Runner) func() {
	old := commandRunner
	commandRunner = r
	return func() { commandRunner = old }
}

// SetLookPathForTest replaces LookPath and returns a restore function.
func SetLookPathForTest(fn func(string) (string, error)) func() {
	old := lookPath
	lookPath = fn
	return func() { lookPath = old }
}

// Run executes an allowed action and writes its JSON result.
func Run(ctx context.Context, action string, out io.Writer, args ...string) error {
	switch action {
	case "facts":
		facts, err := collectFacts(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(facts)
	case "check":
		output, code, err := checkUpdates(ctx)
		return writeResult(out, "check", output, code, err)
	case "apply":
		output, code, err := applyUpdates(ctx)
		return writeResult(out, "apply", output, code, err)
	case "reboot":
		output, code, err := rebootHost(ctx)
		return writeResult(out, "reboot", string(output), code, err)
	case "system-info":
		info, err := collectSystemInfo(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(info)
	case "metrics":
		metrics, err := collectMetrics(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(metrics)
	case "docker-list":
		inventory, err := collectDockerInventory(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(inventory)
	case "docker-check":
		result, err := dockerCheck(ctx, args)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	case "docker-apply":
		result, err := dockerApply(ctx, args)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	case "reboot-check":
		required, err := rebootRequired(ctx)
		result := Result{Action: "reboot-check", OK: err == nil, ExitCode: 0}
		if required {
			result.Output = "reboot required"
		} else {
			result.Output = "no reboot required"
		}
		if err != nil {
			result.Error = err.Error()
		}
		return json.NewEncoder(out).Encode(result)
	default:
		return fmt.Errorf("unknown helper action %q", action)
	}
}

func writeResult(out io.Writer, action, output string, code int, err error) error {
	ok := err == nil && (code == 0 || (action == "check" && code == 100))
	result := Result{Action: action, OK: ok, ExitCode: code, Output: output}
	if err != nil {
		result.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
		return encodeErr
	}
	if err != nil {
		return err
	}
	return nil
}

func collectFacts(ctx context.Context) (Facts, error) {
	osInfo, err := readOSRelease("/etc/os-release")
	if err != nil {
		return Facts{}, err
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	uptime, _ := os.ReadFile("/proc/uptime")
	uptimeSeconds := parseUptime(string(uptime))
	now := time.Now().UTC()
	facts := Facts{
		OSID:           osInfo["ID"],
		OSVersion:      osInfo["VERSION_ID"],
		OSPrettyName:   osInfo["PRETTY_NAME"],
		Kernel:         strings.TrimSpace(string(kernel)),
		PackageManager: detectPackageManager(),
		UptimeSeconds:  uptimeSeconds,
		BootTime:       now.Add(-time.Duration(uptimeSeconds) * time.Second).Format(time.RFC3339),
		DiskFreeBytes:  diskFreeBytes("/"),
		TimeSyncOK:     timeSyncOK(ctx),
		Agent:          buildinfo.Current,
	}
	facts.PendingUpdates = countPending(ctx, facts.PackageManager)
	facts.RebootRequired, _ = rebootRequired(ctx)
	return facts, nil
}

func readOSRelease(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return result, nil
}

func parseUptime(value string) int64 {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 {
		return 0
	}
	return int64(seconds)
}

func detectPackageManager() string {
	candidates := []struct {
		binary string
		name   string
	}{
		{"apt-get", "apt"},
		{"dnf", "dnf"},
		{"zypper", "zypper"},
		{"pacman", "pacman"},
		{"apk", "apk"},
	}
	for _, candidate := range candidates {
		if _, err := lookPath(candidate.binary); err == nil {
			return candidate.name
		}
	}
	return "unknown"
}

func diskFreeBytes(path string) int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	return int64(stat.Bavail) * int64(stat.Bsize)
}

func runBinary(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	path, err := lookPath(name)
	if err != nil {
		return nil, 127, err
	}
	return commandRunner(ctx, path, args...)
}

func timeSyncOK(ctx context.Context) bool {
	output, code, err := runBinary(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil || code != 0 {
		return false
	}
	return strings.TrimSpace(string(output)) == "yes"
}

func countPending(ctx context.Context, packageManager string) int {
	output, code, err := checkCommand(ctx, packageManager)
	if err != nil && code != 100 {
		return 0
	}
	return countPackages(packageManager, string(output))
}

func countPackages(packageManager, output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch packageManager {
		case "apt":
			if strings.HasPrefix(line, "Inst ") {
				count++
			}
		case "dnf":
			if !strings.HasPrefix(line, "Last metadata") && !strings.HasPrefix(line, "Obsoleting") && !strings.HasPrefix(line, "Security:") {
				count++
			}
		case "zypper":
			if strings.HasPrefix(line, "v ") || strings.HasPrefix(line, "v  ") {
				count++
			}
		case "pacman":
			if !strings.HasPrefix(line, "error:") {
				count++
			}
		case "apk":
			if strings.Contains(line, "<") {
				count++
			}
		}
	}
	return count
}

func checkUpdates(ctx context.Context) (string, int, error) {
	packageManager := detectPackageManager()
	output, code, err := checkCommand(ctx, packageManager)
	return string(output), code, err
}

func checkCommand(ctx context.Context, packageManager string) ([]byte, int, error) {
	switch packageManager {
	case "apt":
		return runBinary(ctx, "apt-get", "-s", "upgrade")
	case "dnf":
		return runBinary(ctx, "dnf", "-q", "check-update")
	case "zypper":
		return runBinary(ctx, "zypper", "-q", "list-updates")
	case "pacman":
		return runBinary(ctx, "pacman", "-Qu")
	case "apk":
		return runBinary(ctx, "apk", "version", "-l", "<")
	default:
		return nil, 0, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func applyUpdates(ctx context.Context) (string, int, error) {
	packageManager := detectPackageManager()
	var all bytes.Buffer
	switch packageManager {
	case "apt":
		output, code, err := runBinary(ctx, "apt-get", "update")
		all.Write(output)
		if err != nil || code != 0 {
			return all.String(), code, err
		}
		output, code, err = runBinary(ctx, "apt-get", "-y",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"upgrade")
		all.Write(output)
		return all.String(), code, err
	case "dnf":
		output, code, err := runBinary(ctx, "dnf", "-y", "--refresh", "upgrade")
		return string(output), code, err
	case "zypper":
		output, code, err := runBinary(ctx, "zypper", "--non-interactive", "update")
		return string(output), code, err
	case "pacman":
		output, code, err := runBinary(ctx, "pacman", "-Syu", "--noconfirm")
		return string(output), code, err
	case "apk":
		output, code, err := runBinary(ctx, "apk", "upgrade")
		return string(output), code, err
	default:
		return "", 0, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func rebootHost(ctx context.Context) ([]byte, int, error) {
	// Prefer systemd's non-blocking request so the helper can return its JSON
	// result before the SSH connection drops. Fall back to shutdown(8) on
	// non-systemd targets.
	if _, err := lookPath("systemctl"); err == nil {
		return runBinary(ctx, "systemctl", "reboot", "--no-block")
	}
	return runBinary(ctx, "shutdown", "-r", "now")
}

func rebootRequired(ctx context.Context) (bool, error) {
	osInfo, err := readOSRelease("/etc/os-release")
	if err != nil {
		return false, err
	}
	id := strings.ToLower(osInfo["ID"])
	like := strings.ToLower(osInfo["ID_LIKE"])
	switch {
	case id == "debian" || id == "ubuntu" || strings.Contains(like, "debian"):
		_, err := os.Stat("/var/run/reboot-required")
		return err == nil, nil
	case id == "fedora" || id == "rhel" || id == "centos" || id == "rocky" || id == "almalinux" || strings.Contains(like, "fedora") || strings.Contains(like, "rhel"):
		_, code, err := runBinary(ctx, "needs-restarting", "-r")
		if err != nil {
			return false, nil
		}
		return code == 1, nil
	case id == "opensuse" || id == "sles" || strings.Contains(like, "suse"):
		output, code, err := runBinary(ctx, "zypper", "needs-reboot")
		if err != nil {
			return false, nil
		}
		text := strings.ToLower(string(output))
		return code == 102 || strings.Contains(text, "reboot is required") || strings.Contains(text, "reboot required"), nil
	case id == "arch" || strings.Contains(like, "arch"):
		return kernelChanged(), nil
	case id == "alpine":
		return kernelChanged(), nil
	default:
		return false, nil
	}
}

func kernelChanged() bool {
	running, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	entries, err := os.ReadDir("/usr/lib/modules")
	if err != nil {
		return false
	}
	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}
	if len(versions) == 0 {
		return false
	}
	sort.Strings(versions)
	return strings.TrimSpace(string(running)) != versions[len(versions)-1]
}

func defaultRunner(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = "/"
	cmd.Env = []string{
		"HOME=/root",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"LANG=C",
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
		"NEEDRESTART_MODE=l",
	}
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
			err = nil
		} else if errors.Is(err, context.DeadlineExceeded) {
			return output.Bytes(), 124, err
		} else if errors.Is(err, exec.ErrNotFound) {
			return output.Bytes(), 127, err
		} else {
			return output.Bytes(), 1, err
		}
	}
	return output.Bytes(), code, err
}

type limitedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := maxOutput - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	if b.truncated {
		return append(b.buf.Bytes(), []byte("\n[output truncated]")...)
	}
	return b.buf.Bytes()
}

// ValidateKeyPath rejects relative or non-regular key paths.
func ValidateKeyPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("key path is empty")
	}
	if !filepath.IsAbs(path) {
		return errors.New("key path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("key path must be a regular file")
	}
	return nil
}
