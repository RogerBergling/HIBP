package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
)

type monitorResult struct {
	status  string
	message string
	skip    bool
}

func networkMonitorType(monitorType string) bool {
	return monitorType == "http" || monitorType == "tcp" || monitorType == "ssl"
}

// RunMonitor evaluates enabled monitors and sends alert email. It never
// modifies targets; network probes are read-only and host data comes from the
// collector snapshots.
func (s *Server) RunMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluateMonitors(ctx)
		case <-s.monitorWake:
			s.evaluateMonitors(ctx)
		}
	}
}

func (s *Server) evaluateMonitors(ctx context.Context) {
	s.monitorMu.Lock()
	if s.monitorRunning {
		s.monitorMu.Unlock()
		return
	}
	s.monitorRunning = true
	s.monitorMu.Unlock()
	defer func() {
		s.monitorMu.Lock()
		s.monitorRunning = false
		s.monitorMu.Unlock()
	}()

	monitors, err := s.store.ListMonitors()
	if err != nil {
		slog.Warn("monitor: list monitors", "error", err)
		return
	}
	hosts, err := s.store.ListHosts()
	if err != nil {
		slog.Warn("monitor: list hosts", "error", err)
		return
	}
	hostByID := make(map[string]store.Host, len(hosts))
	for _, host := range hosts {
		hostByID[host.ID] = host
	}
	now := time.Now().UTC()
	for _, monitor := range monitors {
		if !monitor.Enabled {
			continue
		}
		interval := time.Duration(monitor.IntervalSeconds) * time.Second
		if interval < 30*time.Second {
			interval = 30 * time.Second
		}
		if last, err := time.Parse(time.RFC3339Nano, monitor.LastCheckedAt); err == nil && now.Sub(last) < interval {
			continue
		}
		assignments, err := s.store.ListMonitorAssignments(monitor.ID)
		if err != nil {
			slog.Warn("monitor: assignments", "monitor", monitor.Name, "error", err)
			continue
		}
		targets, active, network := resolveMonitorTargets(monitor.Type, assignments, hostByID)
		if !active {
			_ = s.store.SetMonitorChecked(monitor.ID, now.Format(time.RFC3339Nano))
			continue
		}
		results := make([]struct {
			hostID   string
			hostName string
			result   monitorResult
		}, 0)
		if network {
			result := s.evaluateMonitor(ctx, monitor, store.Host{})
			results = append(results, struct {
				hostID   string
				hostName string
				result   monitorResult
			}{result: result})
		} else {
			var mu sync.Mutex
			var wg sync.WaitGroup
			semaphore := make(chan struct{}, 8)
			for _, host := range targets {
				host := host
				wg.Add(1)
				go func() {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()
					result := s.evaluateMonitor(ctx, monitor, host)
					mu.Lock()
					results = append(results, struct {
						hostID   string
						hostName string
						result   monitorResult
					}{hostID: host.ID, hostName: host.Name, result: result})
					mu.Unlock()
				}()
			}
			wg.Wait()
			if len(results) == 0 {
				_ = s.store.SetMonitorChecked(monitor.ID, now.Format(time.RFC3339Nano))
				continue
			}
		}
		_ = s.store.SetMonitorChecked(monitor.ID, now.Format(time.RFC3339Nano))
		for _, entry := range results {
			if entry.result.skip {
				continue
			}
			s.recordMonitorResult(monitor, entry.hostID, entry.hostName, entry.result, now)
		}
	}
}

func resolveMonitorTargets(monitorType string, assignments []store.MonitorAssignment, hosts map[string]store.Host) ([]store.Host, bool, bool) {
	// Network probes run from the controller against the monitor target. They
	// are independent of host state, and a standalone monitor has no
	// assignments at all. Keep them active even if an old assignment pointed at
	// a host that has since been removed.
	if networkMonitorType(monitorType) {
		return nil, true, true
	}
	targets := make(map[string]store.Host)
	active := false
	for _, assignment := range assignments {
		switch assignment.Scope {
		case "fleet":
			active = true
			for id, host := range hosts {
				targets[id] = host
			}
		case "host":
			active = true
			if host, ok := hosts[assignment.Target]; ok {
				targets[host.ID] = host
			}
		case "group":
			for id, host := range hosts {
				if strings.EqualFold(host.GroupName, assignment.Target) {
					active = true
					targets[id] = host
				}
			}
		case "tag":
			for id, host := range hosts {
				for _, tag := range strings.Split(host.Tags, ",") {
					if strings.EqualFold(strings.TrimSpace(tag), assignment.Target) {
						active = true
						targets[id] = host
						break
					}
				}
			}
		}
	}
	result := make([]store.Host, 0, len(targets))
	for _, host := range targets {
		result = append(result, host)
	}
	return result, active && len(result) > 0, false
}

func (s *Server) evaluateMonitor(ctx context.Context, monitor store.Monitor, host store.Host) monitorResult {
	switch monitor.Type {
	case "host.cpu", "host.memory", "host.load", "host.disk":
		return s.evaluateHostMetric(monitor, host)
	case "host.ntp":
		return s.evaluateNTP(monitor, host)
	case "docker.project", "docker.container":
		return s.evaluateDocker(monitor, host)
	case "docker.health":
		return s.evaluateDockerHealth(host)
	case "service.systemd":
		return s.evaluateService(monitor, host)
	case "service.baseline":
		return s.evaluateServiceBaseline(host)
	case "security.auth":
		return s.evaluateAuthFailures(monitor, host)
	case "http":
		if s.demo != nil {
			status, message := s.demo.EvaluateNetworkMonitor(ctx, monitor)
			return monitorResult{status: status, message: message}
		}
		return evaluateHTTP(ctx, monitor)
	case "tcp":
		if s.demo != nil {
			status, message := s.demo.EvaluateNetworkMonitor(ctx, monitor)
			return monitorResult{status: status, message: message}
		}
		return evaluateTCP(monitor)
	case "ssl":
		if s.demo != nil {
			status, message := s.demo.EvaluateNetworkMonitor(ctx, monitor)
			return monitorResult{status: status, message: message}
		}
		return evaluateSSL(monitor)
	default:
		return monitorResult{status: "unknown", message: "unsupported monitor type"}
	}
}

func (s *Server) metricsFreshness(hostID string) time.Duration {
	freshness := 15 * time.Minute
	interval := durationSetting(
		s.store.ResolveSetting(hostID, "collector.metrics_interval", "5m"),
		5*time.Minute,
	)
	if interval*3 > freshness {
		freshness = interval * 3
	}
	return freshness
}

func (s *Server) factsFreshness(hostID string) time.Duration {
	freshness := 30 * time.Hour
	interval := durationSetting(
		s.store.ResolveSetting(hostID, "collector.facts_interval", "12h"),
		12*time.Hour,
	)
	if interval*2 > freshness {
		freshness = interval * 2
	}
	return freshness
}

func (s *Server) evaluateHostMetric(monitor store.Monitor, host store.Host) monitorResult {
	metrics, err := s.store.ListMetrics(host.ID, 1)
	if err != nil || len(metrics) == 0 {
		return monitorResult{status: "unknown", message: "no metrics collected"}
	}
	sample := metrics[len(metrics)-1]
	collected, err := time.Parse(time.RFC3339Nano, sample.CollectedAt)
	if err != nil || time.Since(collected) > s.metricsFreshness(host.ID) {
		return monitorResult{status: "unknown", message: "metrics are stale"}
	}
	value := 0.0
	unit := "%"
	label := monitor.Type
	switch monitor.Type {
	case "host.cpu":
		value = sample.CPUPercent
		label = "CPU"
	case "host.memory":
		value = sample.MemoryPercent
		label = "Memory"
	case "host.load":
		value = sample.Load1
		unit = ""
		label = "Load1"
	case "host.disk":
		snapshot, err := s.store.GetSystemInfo(host.ID)
		if err != nil {
			return monitorResult{status: "unknown", message: "no system information collected"}
		}
		infoCollected, err := time.Parse(time.RFC3339Nano, snapshot.CollectedAt)
		if err != nil || time.Since(infoCollected) > s.factsFreshness(host.ID) {
			return monitorResult{status: "unknown", message: "system information is stale"}
		}
		var info helper.SystemInfo
		if err := json.Unmarshal([]byte(snapshot.PayloadJSON), &info); err != nil {
			return monitorResult{status: "unknown", message: "invalid system information"}
		}
		found := false
		for _, diskInfo := range info.Disks {
			if diskInfo.Mount == monitor.Target {
				value = diskInfo.UsedPercent
				found = true
				break
			}
		}
		if !found {
			return monitorResult{status: "critical", message: fmt.Sprintf("mount %s not found", monitor.Target)}
		}
		label = "Disk " + monitor.Target
	}
	status := "ok"
	if value >= monitor.Critical {
		status = "critical"
	} else if value >= monitor.Warning {
		status = "warning"
	}
	message := fmt.Sprintf("%s %.2f%s (warning %.2f%s, critical %.2f%s)", label, value, unit, monitor.Warning, unit, monitor.Critical, unit)
	return monitorResult{status: status, message: message}
}

func (s *Server) evaluateNTP(monitor store.Monitor, host store.Host) monitorResult {
	facts := host.Facts
	if facts == nil {
		return monitorResult{status: "unknown", message: "no facts collected"}
	}
	if collected, err := time.Parse(time.RFC3339Nano, facts.CollectedAt); err != nil || time.Since(collected) > s.factsFreshness(host.ID) {
		return monitorResult{status: "unknown", message: "facts are stale"}
	}
	if facts.TimeSyncSource == "" {
		return monitorResult{status: "unknown", message: "NTP status is not available"}
	}
	if !facts.TimeSyncOK {
		return monitorResult{status: "critical", message: "clock is not synchronized"}
	}
	if !facts.TimeSyncOffsetKnown {
		return monitorResult{status: "ok", message: "clock synchronized; offset not reported"}
	}
	offset := math.Abs(facts.TimeSyncOffset)
	if monitor.Critical > 0 && offset >= monitor.Critical {
		return monitorResult{status: "critical", message: fmt.Sprintf("clock offset %.3fs (critical %.3fs)", offset, monitor.Critical)}
	}
	if monitor.Warning > 0 && offset >= monitor.Warning {
		return monitorResult{status: "warning", message: fmt.Sprintf("clock offset %.3fs (warning %.3fs)", offset, monitor.Warning)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("clock synchronized; offset %.3fs", offset)}
}

func (s *Server) evaluateDocker(monitor store.Monitor, host store.Host) monitorResult {
	if s.store.ResolveSetting(host.ID, "monitor.docker.enabled", "1") == "0" {
		return monitorResult{status: "ok", message: "Docker monitoring is disabled for this host"}
	}
	projects, containers, unavailable := s.dockerInventoryForMonitor(host)
	if unavailable != nil {
		return *unavailable
	}
	if monitor.Type == "docker.container" && monitor.Target == "*" {
		return evaluateAllContainers(containers)
	}
	if monitor.Type == "docker.project" {
		found := false
		for _, project := range projects {
			if project.Name == monitor.Target {
				found = true
				break
			}
		}
		if !found {
			return monitorResult{status: "critical", message: "Compose project not found"}
		}
		running := 0
		total := 0
		unhealthy := 0
		for _, container := range containers {
			if container.Project != monitor.Target {
				continue
			}
			total++
			if container.State == "running" {
				running++
			}
			if container.Health == "unhealthy" {
				unhealthy++
			}
		}
		if running == 0 {
			return monitorResult{status: "critical", message: fmt.Sprintf("project has no running containers (0/%d)", total)}
		}
		if unhealthy > 0 {
			return monitorResult{status: "critical", message: fmt.Sprintf("%d unhealthy container(s) in project", unhealthy)}
		}
		if running < total {
			return monitorResult{status: "warning", message: fmt.Sprintf("%d/%d containers running", running, total)}
		}
		return monitorResult{status: "ok", message: fmt.Sprintf("%d/%d containers running", running, total)}
	}
	for _, container := range containers {
		if container.Name != monitor.Target {
			continue
		}
		if container.State != "running" {
			return monitorResult{status: "critical", message: "container state: " + container.State}
		}
		switch container.Health {
		case "unhealthy":
			return monitorResult{status: "critical", message: "container is unhealthy"}
		case "starting":
			return monitorResult{status: "warning", message: "container health is starting"}
		}
		return monitorResult{status: "ok", message: "container is running"}
	}
	return monitorResult{status: "critical", message: "container not found"}
}

func (s *Server) evaluateDockerHealth(host store.Host) monitorResult {
	if s.store.ResolveSetting(host.ID, "monitor.docker.enabled", "1") == "0" {
		return monitorResult{status: "ok", message: "Docker monitoring is disabled for this host"}
	}
	_, containers, unavailable := s.dockerInventoryForMonitor(host)
	if unavailable != nil {
		return *unavailable
	}
	running := 0
	var problems []string
	for _, container := range containers {
		if container.State == "running" {
			running++
		}
		switch {
		case strings.EqualFold(container.Health, "unhealthy"):
			problems = append(problems, container.Name+" unhealthy")
		case strings.EqualFold(container.State, "restarting"):
			problems = append(problems, container.Name+" restarting")
		case strings.EqualFold(container.State, "dead"):
			problems = append(problems, container.Name+" dead")
		}
	}
	if len(problems) > 0 {
		return monitorResult{status: "critical", message: "container health: " + monitorListSummary(problems)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("%d/%d containers running", running, len(containers))}
}

// dockerInventoryForMonitor returns cached Docker inventory and a short-circuit
// result when Docker is unavailable, absent, or stale.
func (s *Server) dockerInventoryForMonitor(host store.Host) ([]store.DockerProject, []store.DockerContainer, *monitorResult) {
	if snapshot, err := s.store.GetSystemInfo(host.ID); err == nil {
		var info helper.SystemInfo
		if json.Unmarshal([]byte(snapshot.PayloadJSON), &info) == nil && !info.Docker.Available {
			result := monitorResult{status: "unknown", message: "Docker is not installed", skip: true}
			return nil, nil, &result
		}
	}
	projects, containers, err := s.store.GetDockerInventory(host.ID)
	if err != nil || (len(projects) == 0 && len(containers) == 0) {
		result := monitorResult{status: "unknown", message: "no Docker inventory collected"}
		return nil, nil, &result
	}
	latest := ""
	for _, container := range containers {
		if container.LastSeen > latest {
			latest = container.LastSeen
		}
	}
	for _, project := range projects {
		if project.LastSeen > latest {
			latest = project.LastSeen
		}
	}
	if seen, err := time.Parse(time.RFC3339Nano, latest); err != nil || time.Since(seen) > s.metricsFreshness(host.ID) {
		result := monitorResult{status: "unknown", message: "Docker inventory is stale"}
		return nil, nil, &result
	}
	return projects, containers, nil
}

// evaluateAllContainers is the strict docker.container target "*" mode: every
// known container must be running, and unhealthy/restarting/dead states are
// reported explicitly. It is intentionally stricter than the fleet
// docker.health monitor, which ignores cleanly stopped containers.
func evaluateAllContainers(containers []store.DockerContainer) monitorResult {
	running := 0
	var problems []string
	for _, container := range containers {
		if container.State == "running" {
			running++
		}
		switch {
		case strings.EqualFold(container.Health, "unhealthy"):
			problems = append(problems, container.Name+" unhealthy")
		case strings.EqualFold(container.State, "restarting"):
			problems = append(problems, container.Name+" restarting")
		case strings.EqualFold(container.State, "dead"):
			problems = append(problems, container.Name+" dead")
		case container.State != "" && !strings.EqualFold(container.State, "running"):
			problems = append(problems, container.Name+" "+container.State)
		}
	}
	if len(problems) > 0 {
		return monitorResult{status: "critical", message: "container state: " + monitorListSummary(problems)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("%d/%d containers running", running, len(containers))}
}

func (s *Server) evaluateServiceBaseline(host store.Host) monitorResult {
	if s.store.ResolveSetting(host.ID, "monitor.service_baseline.enabled", "1") == "0" {
		return monitorResult{status: "ok", message: "service baseline monitoring is disabled for this host"}
	}
	if err := s.store.ApplyServiceBaselineDefaultExclusions(host.ID); err != nil {
		return monitorResult{status: "unknown", message: "service baseline exclusions are not available"}
	}
	if snapshot, err := s.store.GetSystemInfo(host.ID); err == nil {
		var info helper.SystemInfo
		if json.Unmarshal([]byte(snapshot.PayloadJSON), &info) == nil && !info.Systemd.UnitsCollected {
			return monitorResult{status: "unknown", message: "systemd unit state is not available", skip: true}
		}
	}
	states, err := s.store.ListServiceStates(host.ID)
	if err != nil {
		return monitorResult{status: "unknown", message: "service state is not available"}
	}
	latest := ""
	for _, state := range states {
		if state.LastSeen > latest {
			latest = state.LastSeen
		}
	}
	if latest == "" {
		return monitorResult{status: "unknown", message: "no service state collected"}
	}
	if seen, err := time.Parse(time.RFC3339Nano, latest); err != nil || time.Since(seen) > s.metricsFreshness(host.ID) {
		return monitorResult{status: "unknown", message: "service state is stale"}
	}
	baseline, err := s.store.ListServiceBaseline(host.ID)
	if err != nil {
		return monitorResult{status: "unknown", message: "service baseline is not available"}
	}
	excluded := make(map[string]bool, len(baseline))
	current := make(map[string]string, len(states))
	for _, item := range baseline {
		if item.Excluded {
			excluded[item.Unit] = true
		}
	}
	for unit := range unitSet(s.store.ResolveSetting(host.ID, "monitor.service_baseline.exclude", "")) {
		excluded[unit] = true
	}
	var failed []string
	for _, state := range states {
		current[state.Unit] = state.State
		if state.State == "failed" && !excluded[state.Unit] {
			failed = append(failed, state.Unit)
		}
	}
	if len(baseline) == 0 {
		if len(failed) > 0 {
			return monitorResult{status: "critical", message: "failed services: " + monitorListSummary(failed)}
		}
		return monitorResult{status: "unknown", message: "no service baseline collected yet"}
	}
	var missing []string
	expected := 0
	for _, item := range baseline {
		if item.Excluded || !item.Expected || excluded[item.Unit] {
			continue
		}
		expected++
		if state, ok := current[item.Unit]; !ok || (state != "running" && state != "failed") {
			missing = append(missing, item.Unit)
		}
	}
	if len(failed) > 0 || len(missing) > 0 {
		parts := make([]string, 0, 2)
		if len(failed) > 0 {
			parts = append(parts, "failed: "+monitorListSummary(failed))
		}
		if len(missing) > 0 {
			parts = append(parts, "not running: "+monitorListSummary(missing))
		}
		return monitorResult{status: "critical", message: strings.Join(parts, "; ")}
	}
	if expected == 0 {
		return monitorResult{status: "ok", message: "no expected baseline services"}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("%d baseline services running", expected)}
}

func (s *Server) evaluateAuthFailures(monitor store.Monitor, host store.Host) monitorResult {
	window := intSetting(s.store.ResolveSetting(host.ID, "events.auth_window_minutes", "10"), 10)
	since := time.Now().UTC().Add(-time.Duration(window) * time.Minute).Format(time.RFC3339Nano)
	count, err := s.store.CountHostEventsSince(host.ID, "auth_failure", since)
	if err != nil {
		return monitorResult{status: "unknown", message: "authentication events are not available"}
	}
	if monitor.Critical > 0 && float64(count) >= monitor.Critical {
		return monitorResult{status: "critical", message: fmt.Sprintf("%d failed authentication events in %dm (critical %.0f)", count, window, monitor.Critical)}
	}
	if monitor.Warning > 0 && float64(count) >= monitor.Warning {
		return monitorResult{status: "warning", message: fmt.Sprintf("%d failed authentication events in %dm (warning %.0f)", count, window, monitor.Warning)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("%d failed authentication events in %dm", count, window)}
}

func monitorListSummary(items []string) string {
	const limit = 8
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:limit], ", ") + fmt.Sprintf(" (+%d more)", len(items)-limit)
}

func (s *Server) evaluateService(monitor store.Monitor, host store.Host) monitorResult {
	if snapshot, err := s.store.GetSystemInfo(host.ID); err == nil {
		var info helper.SystemInfo
		if json.Unmarshal([]byte(snapshot.PayloadJSON), &info) == nil && !info.Systemd.UnitsCollected {
			return monitorResult{status: "unknown", message: "systemd unit state is not available", skip: true}
		}
	}
	state, err := s.store.GetServiceState(host.ID, monitor.Target)
	if err != nil {
		return monitorResult{status: "critical", message: "service is not running or not installed"}
	}
	if seen, err := time.Parse(time.RFC3339Nano, state.LastSeen); err != nil || time.Since(seen) > s.metricsFreshness(host.ID) {
		return monitorResult{status: "unknown", message: "service state is stale"}
	}
	if state.State == "failed" {
		return monitorResult{status: "critical", message: "service is failed"}
	}
	if state.State == "running" {
		return monitorResult{status: "ok", message: "service is running"}
	}
	return monitorResult{status: "warning", message: "service state: " + state.State}
}

func evaluateHTTP(ctx context.Context, monitor store.Monitor) monitorResult {
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, monitor.Target, nil)
	if err != nil {
		return monitorResult{status: "critical", message: err.Error()}
	}
	request.Header.Set("User-Agent", "HIBP-Monitor/0.3")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	started := time.Now()
	response, err := client.Do(request)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return monitorResult{status: "critical", message: "request failed: " + err.Error()}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return monitorResult{status: "critical", message: fmt.Sprintf("HTTP %d in %dms", response.StatusCode, latency)}
	}
	if monitor.Critical > 0 && float64(latency) >= monitor.Critical {
		return monitorResult{status: "critical", message: fmt.Sprintf("HTTP %d in %dms (critical latency %.0fms)", response.StatusCode, latency, monitor.Critical)}
	}
	if monitor.Warning > 0 && float64(latency) >= monitor.Warning {
		return monitorResult{status: "warning", message: fmt.Sprintf("HTTP %d in %dms (warning latency %.0fms)", response.StatusCode, latency, monitor.Warning)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("HTTP %d in %dms", response.StatusCode, latency)}
}

func evaluateTCP(monitor store.Monitor) monitorResult {
	started := time.Now()
	conn, err := net.DialTimeout("tcp", monitor.Target, 10*time.Second)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return monitorResult{status: "critical", message: "TCP connect failed: " + err.Error()}
	}
	_ = conn.Close()
	if monitor.Critical > 0 && float64(latency) >= monitor.Critical {
		return monitorResult{status: "critical", message: fmt.Sprintf("TCP connect %dms (critical %.0fms)", latency, monitor.Critical)}
	}
	if monitor.Warning > 0 && float64(latency) >= monitor.Warning {
		return monitorResult{status: "warning", message: fmt.Sprintf("TCP connect %dms (warning %.0fms)", latency, monitor.Warning)}
	}
	return monitorResult{status: "ok", message: fmt.Sprintf("TCP connect %dms", latency)}
}

func evaluateSSL(monitor store.Monitor) monitorResult {
	host, _, err := net.SplitHostPort(monitor.Target)
	if err != nil {
		return monitorResult{status: "critical", message: "invalid SSL target"}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", monitor.Target, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return monitorResult{status: "critical", message: "TLS connection failed: " + err.Error()}
	}
	defer conn.Close()
	certificates := conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return monitorResult{status: "critical", message: "no peer certificate"}
	}
	expires := certificates[0].NotAfter
	days := time.Until(expires).Hours() / 24
	message := fmt.Sprintf("certificate expires %s (%.1f days)", expires.UTC().Format("2006-01-02"), days)
	if days <= monitor.Critical {
		return monitorResult{status: "critical", message: message}
	}
	if days <= monitor.Warning {
		return monitorResult{status: "warning", message: message}
	}
	return monitorResult{status: "ok", message: message}
}

func (s *Server) recordMonitorResult(monitor store.Monitor, hostID, hostName string, result monitorResult, now time.Time) {
	previous, err := s.store.GetMonitorState(monitor.ID, hostID)
	if err != nil {
		previous = store.MonitorState{MonitorID: monitor.ID, HostID: hostID, Status: "unknown"}
	}
	changedAt := previous.ChangedAt
	if previous.Status != result.status || changedAt == "" {
		changedAt = now.Format(time.RFC3339Nano)
	}
	lastNotified := previous.LastNotified
	notify := false
	recovery := false
	statusChanged := previous.Status != result.status
	if statusChanged {
		if result.status == "ok" {
			// A first successful check is not a recovery. Only alert recovery
			// when the target was previously warning or critical.
			if previous.Status == "warning" || previous.Status == "critical" {
				recovery = true
				notify = true
			}
		} else if result.status != "ok" {
			notify = true
		}
	} else if result.status != "ok" && monitor.RepeatMinutes > 0 {
		if last, err := time.Parse(time.RFC3339Nano, previous.LastNotified); err != nil || now.Sub(last) >= time.Duration(monitor.RepeatMinutes)*time.Minute {
			notify = true
		}
	}
	// Cooldown suppresses repeated reminders of the same state, never a
	// severity transition or a recovery notice.
	if notify && !statusChanged && !recovery {
		if last, err := time.Parse(time.RFC3339Nano, previous.LastNotified); err == nil && monitor.CooldownMinutes > 0 && now.Sub(last) < time.Duration(monitor.CooldownMinutes)*time.Minute {
			notify = false
		}
	}
	// Unknown data is shown in the UI and alert history state, but it is not
	// emailed. This avoids false alarms for hosts that do not have a capability.
	if result.status == "unknown" {
		notify = false
	}
	if notify {
		subject, body := monitorEmail(monitor, hostName, result, recovery)
		cfg, err := s.loadSMTPConfig()
		emailed := false
		emailError := ""
		if err != nil {
			emailError = err.Error()
		} else {
			recipients, recipientErr := s.monitorRecipients(cfg, monitor, result.status, recovery)
			if recipientErr != nil {
				emailError = recipientErr.Error()
			} else if !cfg.Enabled {
				emailError = "SMTP notifications are disabled"
			} else if len(recipients) == 0 {
				emailError = "no email recipients configured"
			} else if sendErr := s.sendEmail(cfg, recipients, subject, body); sendErr != nil {
				emailError = sendErr.Error()
			} else {
				emailed = true
			}
		}
		lastNotified = now.Format(time.RFC3339Nano)
		detail := result.message
		if hostName != "" {
			detail = hostName + ": " + detail
		} else {
			detail = "standalone probe: " + detail
		}
		_ = s.store.AddAlertEvent(store.AlertEvent{
			MonitorID: monitor.ID, HostID: hostID, Status: result.status, Subject: subject,
			Detail: detail, CreatedAt: now.Format(time.RFC3339Nano), Emailed: emailed, Error: emailError,
		})
		_ = s.store.AddAudit("monitor", "alert", "monitor", monitor.ID, subject)
		if emailError != "" {
			slog.Warn("monitor: email not sent", "monitor", monitor.Name, "error", emailError)
		}
	}
	_ = s.store.UpsertMonitorState(store.MonitorState{
		MonitorID: monitor.ID, HostID: hostID, Status: result.status, Message: result.message,
		CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: changedAt, LastNotified: lastNotified,
	})
}

func monitorEmail(monitor store.Monitor, hostName string, result monitorResult, recovery bool) (string, string) {
	severity := strings.ToUpper(result.status)
	if recovery {
		severity = "RECOVERED"
	}
	target := monitor.Target
	if target == "" {
		target = "fleet"
	}
	scope := target
	if hostName != "" {
		scope = hostName + " (" + target + ")"
	}
	hostLabel := hostName
	if hostLabel == "" {
		hostLabel = "standalone probe"
	}
	subject := fmt.Sprintf("[HIBP][%s] %s - %s", severity, monitor.Name, scope)
	body := fmt.Sprintf(`HIBP monitoring alert

Monitor: %s
Type: %s
Target: %s
Host: %s
Status: %s
Detail: %s
Time: %s
`, monitor.Name, monitor.Type, monitor.Target, hostLabel, result.status, result.message,
		time.Now().UTC().Format(time.RFC3339))
	return subject, body
}
