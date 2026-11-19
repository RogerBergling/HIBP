//go:build demo

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

const (
	demoUsername   = "guest"
	demoPassword   = "guest"
	demoTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
)

type demoRuntime struct {
	store *store.Store

	mu      sync.Mutex
	patched map[string]bool
	cleaned map[string]bool
	reboot  map[string]bool
}

func newDemoHooks(st *store.Store) demoHooks {
	return &demoRuntime{
		store:   st,
		patched: map[string]bool{},
		cleaned: map[string]bool{},
		reboot:  map[string]bool{},
	}
}

func (d *demoRuntime) AuthInfo() map[string]any {
	code, _, _ := auth.TOTPCode(demoTOTPSecret, time.Now())
	remaining := auth.TOTPPeriod - int(time.Now().Unix()%int64(auth.TOTPPeriod))
	return map[string]any{
		"username":               demoUsername,
		"password":               demoPassword,
		"totp_secret":            demoTOTPSecret,
		"totp_code":              code,
		"totp_remaining_seconds": remaining,
		"note":                   "Fake fleet. No real hosts, SSH, email, network probes, or package installs are used.",
	}
}

func (d *demoRuntime) AllowTOTPReplay() bool { return true }

func (d *demoRuntime) SendEmail(_ mailer.Config, _ []string, _, _ string) error {
	time.Sleep(50 * time.Millisecond)
	return nil
}

func (d *demoRuntime) TestHost(ctx context.Context, host store.Host, _ string) error {
	if err := demoDelay(ctx, 180*time.Millisecond); err != nil {
		return err
	}
	if key, _ := d.store.GetHostKey(host.ID); key != nil {
		return nil
	}
	key := demoHostKey(host)
	return &remote.KeyError{Kind: "unknown", KeyType: key.KeyType, Fingerprint: key.Fingerprint}
}

func (d *demoRuntime) ProbeHost(ctx context.Context, host store.Host, _ string) (remote.HostKey, error) {
	if err := demoDelay(ctx, 150*time.Millisecond); err != nil {
		return remote.HostKey{}, err
	}
	return demoHostKey(host), nil
}

func (d *demoRuntime) ProbeJump(ctx context.Context, jump remote.JumpTarget) (remote.HostKey, error) {
	if err := demoDelay(ctx, 150*time.Millisecond); err != nil {
		return remote.HostKey{}, err
	}
	return remote.HostKey{KeyType: "ssh-ed25519", Fingerprint: "SHA256:demo-jump-" + shortDemoName(jump.Address)}, nil
}

func (d *demoRuntime) InstallHelper(ctx context.Context, host store.Host, _ []byte, _ string) (string, error) {
	if err := demoDelay(ctx, 900*time.Millisecond); err != nil {
		return "", err
	}
	facts := d.facts(host)
	data, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (d *demoRuntime) EvaluateNetworkMonitor(ctx context.Context, monitor store.Monitor) (string, string) {
	_ = demoDelay(ctx, 120*time.Millisecond)
	target := strings.ToLower(monitor.Target)
	switch monitor.Type {
	case "http":
		switch {
		case strings.Contains(target, "fail"), strings.Contains(target, "down"), strings.Contains(target, "500"):
			return "critical", "HTTP 503 in 38ms (demo failure)"
		case strings.Contains(target, "warn"), strings.Contains(target, "slow"):
			return "warning", "HTTP 200 in 1850ms (demo warning latency)"
		default:
			return "ok", "HTTP 200 in 42ms (demo)"
		}
	case "tcp":
		switch {
		case strings.Contains(target, "fail"), strings.Contains(target, "down"):
			return "critical", "TCP connect failed: connection refused (demo)"
		default:
			return "ok", "TCP connect 8ms (demo)"
		}
	case "ssl":
		return "ok", "certificate expires in 120.0 days (demo)"
	default:
		return "unknown", "unsupported demo monitor"
	}
}

func (d *demoRuntime) RunHelper(ctx context.Context, host store.Host, action, input string, _ time.Duration) (string, int, error) {
	fields := strings.Fields(action)
	base := action
	arg := ""
	if len(fields) > 0 {
		base = fields[0]
		if len(fields) > 1 {
			arg = fields[1]
		}
	}
	switch base {
	case "facts":
		if err := demoDelay(ctx, 350*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.facts(host))
	case "preview":
		if err := demoDelay(ctx, 700*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.preview(host))
	case "check":
		if err := demoDelay(ctx, 450*time.Millisecond); err != nil {
			return "", 0, err
		}
		return "Inst openssl [3.0.13-1] (3.0.14-1 demo-updates)\nInst curl [8.5.0-1] (8.6.0-1 demo-updates)\n", 0, nil
	case "apply":
		if err := demoDelay(ctx, 1400*time.Millisecond); err != nil {
			return "", 0, err
		}
		d.mu.Lock()
		d.patched[host.ID] = true
		d.mu.Unlock()
		return demoJSON(helper.Result{Action: "apply", OK: true, ExitCode: 0, Output: "demo: package transaction applied"})
	case "cleanup-check":
		if err := demoDelay(ctx, 500*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.cleanup(host, false))
	case "cleanup-apply":
		if err := demoDelay(ctx, 1100*time.Millisecond); err != nil {
			return "", 0, err
		}
		d.mu.Lock()
		d.cleaned[host.ID] = true
		d.mu.Unlock()
		return demoJSON(d.cleanup(host, true))
	case "reboot-check":
		if err := demoDelay(ctx, 180*time.Millisecond); err != nil {
			return "", 0, err
		}
		required := d.facts(host).RebootRequired
		out := "no reboot required"
		if required {
			out = "reboot required"
		}
		return demoJSON(helper.Result{Action: "reboot-check", OK: true, ExitCode: 0, Output: out})
	case "reboot":
		if err := demoDelay(ctx, 450*time.Millisecond); err != nil {
			return "", 0, err
		}
		d.mu.Lock()
		d.reboot[host.ID] = true
		d.mu.Unlock()
		return demoJSON(helper.Result{Action: "reboot", OK: true, ExitCode: 0, Output: "demo: reboot requested"})
	case "system-info":
		if err := demoDelay(ctx, 500*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.systemInfo(host))
	case "metrics":
		if err := demoDelay(ctx, 220*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.metrics(host))
	case "docker-list":
		if err := demoDelay(ctx, 400*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.dockerInventory(host))
	case "docker-check":
		if err := demoDelay(ctx, 650*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.dockerCheck(arg))
	case "docker-apply":
		if err := demoDelay(ctx, 1100*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(helper.DockerApplyResult{
			Action: "docker-apply", OK: true, Project: arg, ExitCode: 0,
			DurationSeconds: 0.8, Output: "demo: compose project recreated",
		})
	case "docker-update-all":
		if err := demoDelay(ctx, 1600*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.dockerUpdateAll())
	case "install-package":
		if err := demoDelay(ctx, 900*time.Millisecond); err != nil {
			return "", 0, err
		}
		return demoJSON(d.installPackage(host, input))
	default:
		return "", 0, fmt.Errorf("demo does not implement helper action %q", action)
	}
}

func (d *demoRuntime) facts(host store.Host) helper.Facts {
	facts := helper.Facts{}
	if host.Facts != nil {
		facts = helper.Facts{
			OSID:             strings.ToLower(strings.ReplaceAll(host.Facts.OSPrettyName, " ", "-")),
			OSVersion:        "",
			OSPrettyName:     host.Facts.OSPrettyName,
			Kernel:           host.Facts.Kernel,
			PackageManager:   host.Facts.PackageManager,
			UptimeSeconds:    host.Facts.UptimeSeconds,
			BootTime:         host.Facts.BootTime,
			PendingUpdates:   host.Facts.PendingUpdates,
			OrphanedPackages: host.Facts.OrphanedPackages,
			CleanupSupported: host.Facts.CleanupSupported,
			RebootRequired:   host.Facts.RebootRequired,
			DiskFreeBytes:    host.Facts.DiskFreeBytes,
			TimeSyncOK:       host.Facts.TimeSyncOK,
		}
	}
	d.mu.Lock()
	patched := d.patched[host.ID]
	cleaned := d.cleaned[host.ID]
	rebooted := d.reboot[host.ID]
	d.mu.Unlock()
	if patched {
		facts.PendingUpdates = 0
		facts.RebootRequired = false
	}
	if cleaned {
		facts.OrphanedPackages = 0
	}
	if rebooted {
		facts.RebootRequired = false
	}
	facts.UptimeSeconds = int64(12*86400) + int64(fnvHash(host.Name)%86400)
	facts.BootTime = time.Now().UTC().Add(-time.Duration(facts.UptimeSeconds) * time.Second).Format(time.RFC3339)
	facts.DiskFreeBytes = int64(20+fnvHash(host.Name)%40) << 30
	facts.TimeSyncOK = true
	facts.Agent = buildinfo.Current
	if facts.PackageManager == "" {
		facts.PackageManager = "apt"
	}
	if facts.OSPrettyName == "" {
		facts.OSPrettyName = "Ubuntu 24.04 LTS"
	}
	if facts.Kernel == "" {
		facts.Kernel = "6.8.0-51-generic"
	}
	facts.CleanupSupported = facts.PackageManager == "apt" || facts.PackageManager == "dnf" ||
		facts.PackageManager == "zypper" || facts.PackageManager == "pacman"
	return facts
}

func (d *demoRuntime) preview(host store.Host) helper.PreviewResult {
	facts := d.facts(host)
	result := helper.PreviewResult{
		Action: "preview", OK: true, PackageManager: facts.PackageManager,
		Packages: []helper.PackageChange{}, Counts: map[string]int{},
		Output: "demo: resolved a simulated package transaction",
	}
	d.mu.Lock()
	patched := d.patched[host.ID]
	d.mu.Unlock()
	if patched {
		result.Output = "demo: system is up to date"
		return result
	}
	switch host.Name {
	case "db01", "arch01":
		return result
	case "fedora01":
		result.Packages = []helper.PackageChange{
			{Name: "kernel-core", Action: "upgrade", OldVersion: "6.12.4", NewVersion: "6.12.8", Repository: "updates"},
			{Name: "systemd", Action: "upgrade", OldVersion: "256.9", NewVersion: "256.11", Repository: "updates"},
			{Name: "openssl", Action: "upgrade", OldVersion: "3.2.2", NewVersion: "3.2.4", Repository: "updates"},
			{Name: "containerd", Action: "install", NewVersion: "2.0.2", Repository: "docker-ce"},
		}
	case "kali-lab":
		result.Packages = []helper.PackageChange{
			{Name: "linux-image-amd64", Action: "upgrade", OldVersion: "6.12.9", NewVersion: "6.12.12", Repository: "kali-rolling"},
			{Name: "metasploit-framework", Action: "upgrade", OldVersion: "6.4.1", NewVersion: "6.4.3", Repository: "kali-rolling"},
		}
	case "suse01":
		result.Packages = []helper.PackageChange{
			{Name: "libopenssl3", Action: "upgrade", OldVersion: "3.1.4", NewVersion: "3.1.5", Repository: "update"},
		}
	default:
		result.Packages = []helper.PackageChange{
			{Name: "openssl", Action: "upgrade", OldVersion: "3.0.13-1", NewVersion: "3.0.14-1", Repository: "demo-updates"},
			{Name: "curl", Action: "upgrade", OldVersion: "8.5.0-1", NewVersion: "8.6.0-1", Repository: "demo-updates"},
			{Name: "libssl3", Action: "upgrade", OldVersion: "3.0.13-1", NewVersion: "3.0.14-1", Repository: "demo-updates"},
			{Name: "nginx", Action: "install", NewVersion: "1.24.0-2", Repository: "demo-updates"},
			{Name: "old-python3", Action: "remove", OldVersion: "3.10.12-1"},
		}
	}
	for _, change := range result.Packages {
		result.Counts[change.Action]++
	}
	result.RebootRequired = facts.RebootRequired
	result.ExitCode = 0
	return result
}

func (d *demoRuntime) cleanup(host store.Host, apply bool) helper.CleanupResult {
	facts := d.facts(host)
	result := helper.CleanupResult{
		Action: "cleanup-check", PackageManager: facts.PackageManager,
		Supported: facts.CleanupSupported, Packages: []string{},
	}
	if !result.Supported {
		result.OK = true
		result.Output = "demo: cleanup is not supported for this package manager"
		return result
	}
	d.mu.Lock()
	cleaned := d.cleaned[host.ID]
	d.mu.Unlock()
	if cleaned {
		result.OK = true
		result.Output = "demo: no orphaned packages remain"
		return result
	}
	switch facts.PackageManager {
	case "dnf":
		result.Packages = []string{"kernel-devel-6.12.4", "python3-devel-3.12.4"}
	case "zypper":
		result.Packages = []string{"libfoo1-1.2.3"}
	case "pacman":
		result.Packages = []string{"python-old-3.11.9"}
	default:
		result.Packages = []string{"linux-headers-6.8.0-45", "libpython3.12-dev"}
	}
	result.Count = len(result.Packages)
	result.Remaining = result.Count
	result.OK = true
	if apply {
		result.Action = "cleanup-apply"
		result.Remaining = 0
		result.Output = "demo: removed simulated orphaned packages"
		return result
	}
	result.Output = "demo: found simulated orphaned packages"
	return result
}

func (d *demoRuntime) systemInfo(host store.Host) helper.SystemInfo {
	facts := d.facts(host)
	now := time.Now().UTC().Format(time.RFC3339)
	docker := helper.DockerInfo{}
	if host.Name == "web01" || host.Name == "docker01" {
		docker = helper.DockerInfo{Available: true, Version: "27.3.1", ComposeVersion: "2.29.7"}
	}
	failed := []string{}
	running := []string{"sshd.service", "chronyd.service", "systemd-journald.service"}
	if host.Name == "web01" {
		failed = []string{"nginx.service"}
		running = append(running, "nginx.service", "docker.service")
	}
	return helper.SystemInfo{
		CollectedAt: now, Hostname: host.Name, OS: "linux", OSPrettyName: facts.OSPrettyName,
		Kernel: facts.Kernel, Arch: "x86_64", Virtualization: "kvm",
		UptimeSeconds: uint64(facts.UptimeSeconds), BootTime: facts.BootTime, Processes: 128,
		CPU:          helper.CPUInfo{Model: "Demo vCPU", Cores: 4, UsagePercent: 18.4, Load1: 0.42, Load5: 0.38, Load15: 0.31},
		Memory:       helper.MemoryInfo{TotalBytes: 8 << 30, UsedBytes: 4 << 30, FreeBytes: 4 << 30, AvailableBytes: 5 << 30, UsedPercent: 50.0},
		Swap:         helper.MemoryInfo{TotalBytes: 2 << 30, UsedBytes: 128 << 20, FreeBytes: 1920 << 20, AvailableBytes: 1920 << 20, UsedPercent: 6.25},
		Disks:        []helper.DiskInfo{{Mount: "/", Filesystem: "ext4", TotalBytes: 40 << 30, UsedBytes: 20 << 30, FreeBytes: 20 << 30, UsedPercent: 50.0}},
		Network:      []helper.NetworkInfo{{Name: "eth0", MAC: "02:00:00:00:00:01", Addresses: []string{host.Address + "/24"}}},
		DefaultRoute: "10.20.0.1", DNS: []string{"10.20.0.2", "1.1.1.1"},
		Systemd:   helper.SystemdInfo{Available: true, Version: "255", FailedUnits: failed, RunningServices: 42, RunningUnits: running, UnitsCollected: true},
		Listening: []string{"0.0.0.0:22", "0.0.0.0:80"},
		Docker:    docker,
	}
}

func (d *demoRuntime) metrics(host store.Host) helper.Metrics {
	facts := d.facts(host)
	seed := float64(fnvHash(host.Name)%100) / 17
	t := float64(time.Now().Unix()/60) / 7
	wave := func(offset float64) float64 { return (math.Sin(t+seed+offset) + 1) / 2 }
	return helper.Metrics{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		CPUPercent:  12 + wave(0)*24, MemoryPercent: 38 + wave(1)*22,
		SwapPercent: 2 + wave(2)*8, DiskPercent: 35 + wave(3)*30,
		Load1: 0.2 + wave(4)*0.8, Load5: 0.2 + wave(5)*0.7, Load15: 0.2 + wave(6)*0.6,
		UptimeSeconds: uint64(facts.UptimeSeconds),
		FailedUnits:   []string{}, RunningUnits: []string{"sshd.service", "chronyd.service"},
		ServicesCollected: true,
	}
}

func (d *demoRuntime) dockerInventory(host store.Host) helper.DockerInventory {
	inventory := helper.DockerInventory{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Projects:    []helper.DockerProject{}, Containers: []helper.DockerContainer{},
	}
	if host.Name != "web01" && host.Name != "docker01" {
		inventory.Error = "Docker CLI is not installed"
		return inventory
	}
	inventory.Available = true
	inventory.DockerVersion = "27.3.1"
	inventory.ComposeVersion = "2.29.7"
	inventory.Projects = []helper.DockerProject{
		{Name: "app", Status: "running(2)", ConfigFiles: "/opt/app/compose.yaml", WorkingDir: "/opt/app"},
		{Name: "monitoring", Status: "running(2)", ConfigFiles: "/opt/monitoring/compose.yaml", WorkingDir: "/opt/monitoring"},
	}
	inventory.Containers = []helper.DockerContainer{
		{ID: "demo-app-web", Name: "app-web-1", Image: "ghcr.io/demo/app:2.4.1", Project: "app", Service: "web", State: "running", Status: "Up 3 days (healthy)", Health: "healthy", Ports: "0.0.0.0:8080->8080/tcp", CreatedAt: "2026-11-01T10:00:00Z"},
		{ID: "demo-app-worker", Name: "app-worker-1", Image: "ghcr.io/demo/app:2.4.1", Project: "app", Service: "worker", State: "running", Status: "Up 3 days (healthy)", Health: "healthy", CreatedAt: "2026-11-01T10:00:00Z"},
		{ID: "demo-mon-grafana", Name: "monitoring-grafana-1", Image: "grafana/grafana:11.3.0", Project: "monitoring", Service: "grafana", State: "running", Status: "Up 12 days", Health: "", Ports: "0.0.0.0:3000->3000/tcp", CreatedAt: "2026-10-20T09:00:00Z"},
		{ID: "demo-mon-prom", Name: "monitoring-prometheus-1", Image: "prom/prometheus:v3.0.1", Project: "monitoring", Service: "prometheus", State: "running", Status: "Up 12 days", Health: "", CreatedAt: "2026-10-20T09:00:00Z"},
	}
	return inventory
}

func (d *demoRuntime) dockerCheck(project string) helper.DockerCheckResult {
	result := helper.DockerCheckResult{
		Action: "docker-check", OK: true, Project: project, DurationSeconds: 0.5,
		Services: []helper.DockerServiceUpdate{}, Output: "demo: pulled and compared images",
	}
	if project == "app" {
		result.Services = []helper.DockerServiceUpdate{
			{Service: "web", Image: "ghcr.io/demo/app:2.5.0", BeforeID: "sha256:old", AfterID: "sha256:new", Status: "update-available"},
			{Service: "worker", Image: "ghcr.io/demo/app:2.4.1", BeforeID: "sha256:same", AfterID: "sha256:same", Status: "up-to-date"},
		}
		return result
	}
	result.Services = []helper.DockerServiceUpdate{
		{Service: "grafana", Image: "grafana/grafana:11.3.0", BeforeID: "sha256:g", AfterID: "sha256:g", Status: "up-to-date"},
	}
	return result
}

func (d *demoRuntime) dockerUpdateAll() helper.DockerUpdateAllResult {
	return helper.DockerUpdateAllResult{
		Action: "docker-update-all", OK: true, Updated: 1, Skipped: 1, Failed: 0, DurationSeconds: 1.4,
		Projects: []helper.DockerProjectUpdateResult{
			{Name: "app", Action: "updated", OK: true},
			{Name: "monitoring", Action: "unchanged", OK: true},
		},
	}
}

func (d *demoRuntime) installPackage(host store.Host, input string) helper.PackageInstallResult {
	facts := d.facts(host)
	result := helper.PackageInstallResult{
		Action: "install-package", OK: true, ExitCode: 0,
		PackageManager: facts.PackageManager,
		Output:         "demo: package installation simulated; nothing was executed",
	}
	var request helper.InstallPackageRequest
	if err := json.Unmarshal([]byte(input), &request); err == nil {
		result.Package = request.Filename
		result.SHA256 = request.SHA256
	}
	return result
}

func demoJSON(value any) (string, int, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", 0, err
	}
	return string(data), 0, nil
}

func demoDelay(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func demoHostKey(host store.Host) remote.HostKey {
	return remote.HostKey{KeyType: "ssh-ed25519", Fingerprint: "SHA256:demo-" + shortDemoName(host.Name)}
}

func shortDemoName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "-", ".", "-", ":", "-").Replace(value)
	if len(value) > 32 {
		value = value[:32]
	}
	return value
}

func fnvHash(value string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return h.Sum32()
}
