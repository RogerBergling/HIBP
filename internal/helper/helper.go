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
	OSID             string         `json:"os_id"`
	OSVersion        string         `json:"os_version"`
	OSPrettyName     string         `json:"os_pretty_name"`
	Kernel           string         `json:"kernel"`
	PackageManager   string         `json:"package_manager"`
	UptimeSeconds    int64          `json:"uptime_seconds"`
	BootTime         string         `json:"boot_time"`
	PendingUpdates   int            `json:"pending_updates"`
	OrphanedPackages int            `json:"orphaned_packages"`
	CleanupSupported bool           `json:"cleanup_supported"`
	RebootRequired   bool           `json:"reboot_required"`
	DiskFreeBytes    int64          `json:"disk_free_bytes"`
	TimeSyncOK       bool           `json:"time_sync_ok"`
	Agent            buildinfo.Info `json:"agent"`
}

// CleanupResult is the JSON contract for cleanup-check and cleanup-apply.
type CleanupResult struct {
	Action         string   `json:"action"`
	OK             bool     `json:"ok"`
	Supported      bool     `json:"supported"`
	PackageManager string   `json:"package_manager"`
	Packages       []string `json:"packages"`
	Count          int      `json:"count"`
	Remaining      int      `json:"remaining"`
	ExitCode       int      `json:"exit_code"`
	Output         string   `json:"output"`
	Error          string   `json:"error,omitempty"`
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
	case "facts-full":
		facts, err := collectFactsWithMode(ctx, true)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(facts)
	case "preview":
		return json.NewEncoder(out).Encode(previewUpdates(ctx))
	case "preview-full":
		return json.NewEncoder(out).Encode(previewUpdatesWithMode(ctx, true))
	case "check":
		output, code, err := checkUpdates(ctx)
		return writeResult(out, "check", output, code, err)
	case "check-full":
		output, code, err := checkUpdatesWithMode(ctx, true)
		return writeResult(out, "check-full", output, code, err)
	case "apply":
		output, code, err := applyUpdates(ctx)
		return writeResult(out, "apply", output, code, err)
	case "apply-full":
		output, code, err := applyUpdatesWithMode(ctx, true)
		return writeResult(out, "apply-full", output, code, err)
	case "cleanup-check":
		result, err := cleanupCheck(ctx)
		return writeCleanupResult(out, result, err)
	case "cleanup-apply":
		result, err := cleanupApply(ctx)
		return writeCleanupResult(out, result, err)
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
	case "docker-update-all":
		if len(args) != 0 {
			return errors.New("docker-update-all does not accept arguments")
		}
		result, err := dockerUpdateAll(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(result)
	case "install-package":
		if len(args) != 0 {
			return errors.New("install-package does not accept command-line arguments")
		}
		return installPackage(ctx, os.Stdin, out)
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

func writeCleanupResult(out io.Writer, result CleanupResult, err error) error {
	if result.Packages == nil {
		result.Packages = []string{}
	}
	result.Count = len(result.Packages)
	if err != nil {
		result.OK = false
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
	return collectFactsWithMode(ctx, false)
}

func collectFactsWithMode(ctx context.Context, fullUpgrade bool) (Facts, error) {
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
	facts.PendingUpdates = countPending(ctx, facts.PackageManager, fullUpgrade)
	facts.CleanupSupported = cleanupSupported(facts.PackageManager)
	if facts.CleanupSupported {
		facts.OrphanedPackages, _ = countOrphaned(ctx, facts.PackageManager)
	}
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

func countPending(ctx context.Context, packageManager string, fullUpgrade bool) int {
	output, code, err := checkCommand(ctx, packageManager, fullUpgrade)
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
	return checkUpdatesWithMode(ctx, false)
}

func checkUpdatesWithMode(ctx context.Context, fullUpgrade bool) (string, int, error) {
	packageManager := detectPackageManager()
	output, code, err := checkCommand(ctx, packageManager, fullUpgrade)
	return string(output), code, err
}

func checkCommand(ctx context.Context, packageManager string, fullUpgrade bool) ([]byte, int, error) {
	switch packageManager {
	case "apt":
		// Refresh package metadata before simulating. Kali and other rolling
		// targets can have stale lists, which previously made a host with many
		// available updates report zero.
		updateOutput, _, _ := runBinary(ctx, "apt-get", "update")
		output, code, err := runBinary(ctx, "apt-get", "-s", aptUpgradeActionForMode(fullUpgrade))
		if len(updateOutput) > 0 {
			if updateOutput[len(updateOutput)-1] != '\n' {
				updateOutput = append(updateOutput, '\n')
			}
			output = append(updateOutput, output...)
		}
		return output, code, err
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

// aptUpgradeAction keeps the conservative Debian/Ubuntu upgrade behavior but
// uses full-upgrade on Kali. Kali is a rolling distribution; ordinary upgrade
// commonly holds back packages that need dependency changes, which made the
// pending count look like zero even when many updates were available.
func aptUpgradeAction() string {
	return aptUpgradeActionForMode(false)
}

func aptUpgradeActionForMode(fullUpgrade bool) string {
	if fullUpgrade {
		return "full-upgrade"
	}
	info, err := readOSRelease("/etc/os-release")
	if err != nil {
		return "upgrade"
	}
	return aptUpgradeActionFor(info["ID"], info["ID_LIKE"])
}

func aptUpgradeActionFor(id, like string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	like = strings.ToLower(strings.TrimSpace(like))
	if id == "kali" || strings.Contains(like, "kali") {
		return "full-upgrade"
	}
	return "upgrade"
}

func applyUpdates(ctx context.Context) (string, int, error) {
	return applyUpdatesWithMode(ctx, false)
}

func applyUpdatesWithMode(ctx context.Context, fullUpgrade bool) (string, int, error) {
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
			aptUpgradeActionForMode(fullUpgrade))
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

func cleanupSupported(packageManager string) bool {
	switch packageManager {
	case "apt", "dnf", "zypper", "pacman":
		return true
	default:
		return false
	}
}

func countOrphaned(ctx context.Context, packageManager string) (int, error) {
	packages, _, _, err := cleanupPreview(ctx, packageManager)
	if err != nil {
		return 0, err
	}
	return len(packages), nil
}

func cleanupCheck(ctx context.Context) (CleanupResult, error) {
	packageManager := detectPackageManager()
	result := CleanupResult{
		Action: "cleanup-check", PackageManager: packageManager,
		Supported: cleanupSupported(packageManager), Packages: []string{},
	}
	if !result.Supported {
		result.OK = true
		result.Output = "orphan package cleanup is not supported for " + packageManager
		return result, nil
	}
	packages, output, code, err := cleanupPreview(ctx, packageManager)
	result.Output = output
	result.ExitCode = code
	result.Packages = packages
	result.Count = len(packages)
	result.Remaining = len(packages)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	if !cleanupExitOK(packageManager, code, packages) {
		result.Error = fmt.Sprintf("package manager exited with code %d", code)
		return result, nil
	}
	result.OK = true
	return result, nil
}

func cleanupApply(ctx context.Context) (CleanupResult, error) {
	packageManager := detectPackageManager()
	result := CleanupResult{
		Action: "cleanup-apply", PackageManager: packageManager,
		Supported: cleanupSupported(packageManager), Packages: []string{},
	}
	if !result.Supported {
		result.OK = true
		result.Output = "orphan package cleanup is not supported for " + packageManager
		return result, nil
	}

	// Preview first. The apply action never accepts package names from the
	// controller; it removes only what the local package manager reports.
	packages, previewOutput, previewCode, err := cleanupPreview(ctx, packageManager)
	result.Output = previewOutput
	result.ExitCode = previewCode
	result.Packages = packages
	result.Count = len(packages)
	result.Remaining = len(packages)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	if !cleanupExitOK(packageManager, previewCode, packages) {
		result.Error = fmt.Sprintf("package manager exited with code %d", previewCode)
		return result, nil
	}
	if len(packages) == 0 {
		result.OK = true
		result.Output = previewOutput + "\nNo orphaned packages to remove."
		return result, nil
	}

	output, code, err := cleanupRemove(ctx, packageManager, packages)
	result.Output = previewOutput + "\n" + output
	result.ExitCode = code
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	if code != 0 {
		result.Error = fmt.Sprintf("package manager exited with code %d", code)
		return result, nil
	}

	remaining, _, _, recheckErr := cleanupPreview(ctx, packageManager)
	if recheckErr != nil {
		result.Remaining = -1
	} else {
		result.Remaining = len(remaining)
	}
	result.OK = true
	return result, nil
}

func cleanupPreview(ctx context.Context, packageManager string) ([]string, string, int, error) {
	switch packageManager {
	case "apt":
		output, code, err := runBinary(ctx, "apt-get", "-s", "autoremove")
		return parseAptAutoremove(string(output)), string(output), code, err
	case "dnf":
		// repoquery --unneeded is the DNF4/DNF5 equivalent of the autoremove
		// preview. Fall back to the older list --autoremove form if this DNF
		// build does not provide repoquery.
		output, code, err := runBinary(ctx, "dnf", "-q", "repoquery", "--unneeded", "--installed", "--qf", "%{name}")
		if err == nil && code == 0 {
			return parseDNFPackages(string(output)), string(output), code, nil
		}
		fallback, fallbackCode, fallbackErr := runBinary(ctx, "dnf", "-q", "list", "--autoremove")
		if fallbackErr == nil && fallbackCode == 0 {
			return parseDNFList(string(fallback)), string(output) + "\n" + string(fallback), fallbackCode, nil
		}
		return parseDNFPackages(string(output)), string(output), code, err
	case "zypper":
		output, code, err := runBinary(ctx, "zypper", "-q", "--non-interactive", "--no-refresh", "packages", "--unneeded")
		return parseZypperUnneeded(string(output)), string(output), code, err
	case "pacman":
		output, code, err := runBinary(ctx, "pacman", "-Qdtq")
		packages := parsePacmanOrphans(string(output))
		if code == 1 && len(packages) == 0 {
			code = 0
		}
		return packages, string(output), code, err
	default:
		return nil, "", 0, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func cleanupRemove(ctx context.Context, packageManager string, packages []string) (string, int, error) {
	switch packageManager {
	case "apt":
		output, code, err := runBinary(ctx, "apt-get", "-y",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"autoremove")
		return string(output), code, err
	case "dnf":
		output, code, err := runBinary(ctx, "dnf", "-y", "autoremove")
		return string(output), code, err
	case "zypper":
		names := safePackageNames(packages)
		if len(names) == 0 {
			return "No orphaned packages to remove.", 0, nil
		}
		args := append([]string{"--non-interactive", "remove", "--clean-deps", "--"}, names...)
		output, code, err := runBinary(ctx, "zypper", args...)
		return string(output), code, err
	case "pacman":
		names := safePackageNames(packages)
		if len(names) == 0 {
			return "No orphaned packages to remove.", 0, nil
		}
		args := append([]string{"-R", "--noconfirm", "--"}, names...)
		output, code, err := runBinary(ctx, "pacman", args...)
		return string(output), code, err
	default:
		return "", 0, fmt.Errorf("unsupported package manager %q", packageManager)
	}
}

func cleanupExitOK(packageManager string, code int, packages []string) bool {
	if code == 0 {
		return true
	}
	return (packageManager == "dnf" || packageManager == "pacman") && code == 1 && len(packages) == 0
}

func safePackageNames(values []string) []string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		if safePackageName(value) {
			names = append(names, value)
		}
	}
	return names
}

func safePackageName(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '+' || char == '-' || char == '.' || char == '_' || char == ':' || char == '@':
		default:
			return false
		}
	}
	return true
}

func parseAptAutoremove(output string) []string {
	var packages []string
	inSection := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "The following packages will be REMOVED:") {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}
		for _, name := range strings.Fields(trimmed) {
			if safePackageName(name) {
				packages = appendUnique(packages, name)
			}
		}
	}
	return packages
}

func parseDNFList(output string) []string {
	var packages []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "Last metadata") ||
			strings.HasPrefix(trimmed, "Dependencies resolved") ||
			strings.HasPrefix(trimmed, "Transaction Summary") ||
			strings.HasPrefix(trimmed, "Installed Packages") ||
			strings.HasPrefix(trimmed, "Available Packages") ||
			strings.HasPrefix(trimmed, "Error:") ||
			strings.HasPrefix(trimmed, "Problem:") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || fields[0] == "Name" {
			continue
		}
		name := fields[0]
		if dot := strings.LastIndex(name, "."); dot > 0 && isRPMArch(name[dot+1:]) {
			name = name[:dot]
		}
		if safePackageName(name) {
			packages = appendUnique(packages, name)
		}
	}
	return packages
}

func parseDNFPackages(output string) []string {
	var packages []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "Last metadata") ||
			strings.HasPrefix(trimmed, "Error:") ||
			strings.HasPrefix(trimmed, "Problem:") {
			continue
		}
		name := strings.Fields(trimmed)[0]
		if safePackageName(name) {
			packages = appendUnique(packages, name)
		}
	}
	return packages
}

func parseZypperUnneeded(output string) []string {
	var packages []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 4 {
			continue
		}
		// "i" is automatically installed; "i+" is user-installed and must not
		// be removed by an autoremove-style cleanup.
		if strings.TrimSpace(fields[0]) != "i" {
			continue
		}
		name := strings.TrimSpace(fields[2])
		if name == "" || name == "Name" {
			continue
		}
		if safePackageName(name) {
			packages = appendUnique(packages, name)
		}
	}
	return packages
}

func parsePacmanOrphans(output string) []string {
	var packages []string
	for _, line := range strings.Split(output, "\n") {
		for _, name := range strings.Fields(line) {
			if safePackageName(name) {
				packages = appendUnique(packages, name)
			}
		}
	}
	return packages
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func isRPMArch(value string) bool {
	switch value {
	case "x86_64", "noarch", "aarch64", "armv7hl", "armv6hl", "i686", "i586", "ppc64le", "ppc64", "s390x", "riscv64":
		return true
	default:
		return false
	}
}

func rebootHost(ctx context.Context) ([]byte, int, error) {
	// Prefer systemd's non-blocking request so the helper can return its JSON
	// result before the SSH connection drops. Fall back to shutdown(8) on
	// non-systemd targets, and also when systemctl exists but the request fails.
	if _, err := lookPath("systemctl"); err == nil {
		output, code, runErr := runBinary(ctx, "systemctl", "reboot", "--no-block")
		if runErr == nil && code == 0 {
			return output, code, nil
		}
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
	sort.Slice(versions, func(i, j int) bool {
		return compareKernelVersions(versions[i], versions[j]) < 0
	})
	return strings.TrimSpace(string(running)) != versions[len(versions)-1]
}

// compareKernelVersions compares dotted/dashed version strings numerically so
// 6.12 sorts after 6.9. A lexical sort would report the wrong newest kernel.
func compareKernelVersions(a, b string) int {
	parts := func(value string) []string {
		return strings.FieldsFunc(value, func(r rune) bool {
			return r == '.' || r == '-' || r == '_' || r == '+'
		})
	}
	left, right := parts(a), parts(b)
	for index := 0; index < len(left) || index < len(right); index++ {
		if index >= len(left) {
			return -1
		}
		if index >= len(right) {
			return 1
		}
		leftNumber, leftErr := strconv.Atoi(left[index])
		rightNumber, rightErr := strconv.Atoi(right[index])
		if leftErr == nil && rightErr == nil {
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
			continue
		}
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
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
