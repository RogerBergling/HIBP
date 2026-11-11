package helper

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// SystemInfo is a bounded, read-only host snapshot. It deliberately omits
// environment variables, process arguments, and other potentially secret data.
type SystemInfo struct {
	CollectedAt    string        `json:"collected_at"`
	Hostname       string        `json:"hostname"`
	OS             string        `json:"os"`
	OSPrettyName   string        `json:"os_pretty_name"`
	Kernel         string        `json:"kernel"`
	Arch           string        `json:"arch"`
	Virtualization string        `json:"virtualization"`
	UptimeSeconds  uint64        `json:"uptime_seconds"`
	BootTime       string        `json:"boot_time"`
	Processes      uint64        `json:"processes"`
	CPU            CPUInfo       `json:"cpu"`
	Memory         MemoryInfo    `json:"memory"`
	Swap           MemoryInfo    `json:"swap"`
	Disks          []DiskInfo    `json:"disks"`
	Network        []NetworkInfo `json:"network"`
	DefaultRoute   string        `json:"default_route"`
	DNS            []string      `json:"dns"`
	Systemd        SystemdInfo   `json:"systemd"`
	Listening      []string      `json:"listening"`
	Docker         DockerInfo    `json:"docker"`
}

type CPUInfo struct {
	Model        string  `json:"model"`
	Cores        int     `json:"cores"`
	UsagePercent float64 `json:"usage_percent"`
	Load1        float64 `json:"load1"`
	Load5        float64 `json:"load5"`
	Load15       float64 `json:"load15"`
}

type MemoryInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	FreeBytes      uint64  `json:"free_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type DiskInfo struct {
	Mount       string  `json:"mount"`
	Filesystem  string  `json:"filesystem"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

type NetworkInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

type SystemdInfo struct {
	Available       bool     `json:"available"`
	Version         string   `json:"version"`
	FailedUnits     []string `json:"failed_units"`
	RunningServices int      `json:"running_services"`
	RunningUnits    []string `json:"running_units,omitempty"`
	UnitsCollected  bool     `json:"units_collected,omitempty"`
}

type DockerInfo struct {
	Available      bool   `json:"available"`
	Version        string `json:"version"`
	ComposeVersion string `json:"compose_version"`
	Error          string `json:"error,omitempty"`
}

// Metrics is the lightweight sample used for time-series graphs.
type Metrics struct {
	CollectedAt   string   `json:"collected_at"`
	CPUPercent    float64  `json:"cpu_percent"`
	MemoryPercent float64  `json:"memory_percent"`
	SwapPercent   float64  `json:"swap_percent"`
	DiskPercent   float64  `json:"disk_percent"`
	Load1         float64  `json:"load1"`
	Load5         float64  `json:"load5"`
	Load15        float64  `json:"load15"`
	UptimeSeconds uint64   `json:"uptime_seconds"`
	FailedUnits   []string `json:"failed_units,omitempty"`
	RunningUnits  []string `json:"running_units,omitempty"`
	// ServicesCollected distinguishes an empty service list from an older
	// helper that cannot report unit names. The controller must not clear
	// cached service state when an old helper is still installed.
	ServicesCollected bool `json:"services_collected,omitempty"`
}

func collectSystemInfo(ctx context.Context) (SystemInfo, error) {
	info := SystemInfo{CollectedAt: time.Now().UTC().Format(time.RFC3339)}
	hostInfo, err := host.InfoWithContext(ctx)
	if err == nil {
		info.Hostname = hostInfo.Hostname
		info.OS = strings.TrimSpace(hostInfo.Platform + " " + hostInfo.PlatformVersion)
		info.Kernel = hostInfo.KernelVersion
		info.Arch = hostInfo.KernelArch
		if info.Arch == "" {
			info.Arch = runtime.GOARCH
		}
		info.UptimeSeconds = hostInfo.Uptime
		info.Processes = hostInfo.Procs
		if hostInfo.BootTime > 0 {
			info.BootTime = time.Unix(int64(hostInfo.BootTime), 0).UTC().Format(time.RFC3339)
		}
		if hostInfo.VirtualizationSystem != "" {
			info.Virtualization = hostInfo.VirtualizationSystem
			if hostInfo.VirtualizationRole != "" {
				info.Virtualization += "/" + hostInfo.VirtualizationRole
			}
		} else {
			info.Virtualization = "none"
		}
	}
	if osInfo, err := readOSRelease("/etc/os-release"); err == nil {
		info.OSPrettyName = osInfo["PRETTY_NAME"]
		info.OS = strings.TrimSpace(osInfo["ID"] + " " + osInfo["VERSION_ID"])
	}
	info.CPU = collectCPU(ctx)
	info.Memory = collectMemory(ctx)
	info.Swap = collectSwap(ctx)
	info.Disks = collectDisks(ctx)
	info.Network = collectNetwork()
	info.DefaultRoute = defaultRoute()
	info.DNS = dnsServers()
	info.Systemd = collectSystemd(ctx)
	info.Listening = collectListening(ctx)
	info.Docker = collectDockerInfo(ctx)
	return info, nil
}

func collectMetrics(ctx context.Context) (Metrics, error) {
	metrics := Metrics{CollectedAt: time.Now().UTC().Format(time.RFC3339)}
	if values, err := cpu.PercentWithContext(ctx, 200*time.Millisecond, false); err == nil && len(values) > 0 {
		metrics.CPUPercent = round2(values[0])
	}
	if memory, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		metrics.MemoryPercent = round2(memory.UsedPercent)
	}
	if swap, err := mem.SwapMemoryWithContext(ctx); err == nil {
		metrics.SwapPercent = round2(swap.UsedPercent)
	}
	if usage, err := disk.UsageWithContext(ctx, "/"); err == nil {
		metrics.DiskPercent = round2(usage.UsedPercent)
	}
	if avg, err := load.AvgWithContext(ctx); err == nil {
		metrics.Load1 = round2(avg.Load1)
		metrics.Load5 = round2(avg.Load5)
		metrics.Load15 = round2(avg.Load15)
	}
	if hostInfo, err := host.InfoWithContext(ctx); err == nil {
		metrics.UptimeSeconds = hostInfo.Uptime
	}
	systemd := collectSystemd(ctx)
	metrics.FailedUnits = systemd.FailedUnits
	metrics.RunningUnits = systemd.RunningUnits
	metrics.ServicesCollected = systemd.UnitsCollected
	return metrics, nil
}

func collectCPU(ctx context.Context) CPUInfo {
	var result CPUInfo
	if values, err := cpu.InfoWithContext(ctx); err == nil && len(values) > 0 {
		result.Model = strings.TrimSpace(values[0].ModelName)
	}
	if cores, err := cpu.CountsWithContext(ctx, true); err == nil {
		result.Cores = cores
	}
	if values, err := cpu.PercentWithContext(ctx, 200*time.Millisecond, false); err == nil && len(values) > 0 {
		result.UsagePercent = round2(values[0])
	}
	if avg, err := load.AvgWithContext(ctx); err == nil {
		result.Load1 = round2(avg.Load1)
		result.Load5 = round2(avg.Load5)
		result.Load15 = round2(avg.Load15)
	}
	return result
}

func collectMemory(ctx context.Context) MemoryInfo {
	value, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return MemoryInfo{}
	}
	return MemoryInfo{TotalBytes: value.Total, UsedBytes: value.Used, AvailableBytes: value.Available, UsedPercent: round2(value.UsedPercent)}
}

func collectSwap(ctx context.Context) MemoryInfo {
	value, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return MemoryInfo{}
	}
	return MemoryInfo{TotalBytes: value.Total, UsedBytes: value.Used, FreeBytes: value.Free, UsedPercent: round2(value.UsedPercent)}
}

func collectDisks(ctx context.Context) []DiskInfo {
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil
	}
	skip := map[string]bool{
		"tmpfs": true, "devtmpfs": true, "proc": true, "sysfs": true, "cgroup": true,
		"cgroup2": true, "overlay": true, "squashfs": true, "mqueue": true, "hugetlbfs": true,
		"debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true,
		"configfs": true, "fusectl": true, "autofs": true, "binfmt_misc": true, "nsfs": true,
		"rpc_pipefs": true, "nfsd": true, "erofs": true,
	}
	var result []DiskInfo
	for _, partition := range partitions {
		if partition.Mountpoint == "" || skip[partition.Fstype] {
			continue
		}
		usage, err := disk.UsageWithContext(ctx, partition.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}
		result = append(result, DiskInfo{
			Mount: partition.Mountpoint, Filesystem: partition.Fstype,
			TotalBytes: usage.Total, UsedBytes: usage.Used, FreeBytes: usage.Free,
			UsedPercent: round2(usage.UsedPercent),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Mount < result[j].Mount })
	if len(result) > 30 {
		result = result[:30]
	}
	return result
}

func collectNetwork() []NetworkInfo {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var result []NetworkInfo
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		item := NetworkInfo{Name: iface.Name, MAC: iface.HardwareAddr.String()}
		addresses, err := iface.Addrs()
		if err == nil {
			for _, address := range addresses {
				item.Addresses = append(item.Addresses, address.String())
			}
		}
		sort.Strings(item.Addresses)
		if len(item.Addresses) > 10 {
			item.Addresses = item.Addresses[:10]
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func defaultRoute() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gateway, err := hex.DecodeString(fields[2])
		if err != nil || len(gateway) != 4 {
			continue
		}
		// /proc/net/route stores the gateway in little-endian byte order.
		return net.IPv4(gateway[3], gateway[2], gateway[1], gateway[0]).String()
	}
	return ""
}

func dnsServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var result []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			result = append(result, fields[1])
		}
		if len(result) >= 5 {
			break
		}
	}
	return result
}

func collectSystemd(ctx context.Context) SystemdInfo {
	if _, err := lookPath("systemctl"); err != nil {
		return SystemdInfo{}
	}
	result := SystemdInfo{Available: true}
	if output, _, err := runBinary(ctx, "systemctl", "--version"); err == nil {
		line := strings.SplitN(string(output), "\n", 2)[0]
		result.Version = strings.TrimSpace(strings.TrimPrefix(line, "systemd"))
	}
	if output, code, err := runBinary(ctx, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager"); err == nil && code == 0 {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				result.FailedUnits = append(result.FailedUnits, fields[0])
			}
			if len(result.FailedUnits) >= 20 {
				break
			}
		}
	}
	if output, code, err := runBinary(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager"); err == nil && code == 0 {
		result.UnitsCollected = true
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			result.RunningServices++
			if len(result.RunningUnits) < 500 {
				result.RunningUnits = append(result.RunningUnits, fields[0])
			}
		}
	}
	return result
}

func collectListening(ctx context.Context) []string {
	if _, err := lookPath("ss"); err != nil {
		return nil
	}
	output, code, err := runBinary(ctx, "ss", "-H", "-lntu", "-p")
	if err != nil || code != 0 {
		return nil
	}
	var result []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
		if len(result) >= 100 {
			break
		}
	}
	return result
}

func collectDockerInfo(ctx context.Context) DockerInfo {
	result := DockerInfo{}
	if _, err := lookPath("docker"); err != nil {
		return result
	}
	result.Available = true
	if output, code, err := runBinary(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err == nil && code == 0 {
		result.Version = strings.TrimSpace(string(output))
	} else if err != nil {
		result.Error = err.Error()
	}
	if output, code, err := runBinary(ctx, "docker", "compose", "version", "--short"); err == nil && code == 0 {
		result.ComposeVersion = strings.TrimSpace(string(output))
	}
	return result
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}
