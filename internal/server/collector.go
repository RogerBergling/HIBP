package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
)

type collectorHostState struct {
	nextMetrics     time.Time
	nextFacts       time.Time
	metricsInterval time.Duration
	factsInterval   time.Duration
	retentionDays   int
	enabled         bool
	settingsLoaded  time.Time
	metricsRunning  bool
	factsRunning    bool
}

// RunCollector is the always-on collection loop. It intentionally runs only
// while the server is unlocked and never prompts for credentials. Scheduled
// collection therefore requires the restricted NOPASSWD helper rule.
func (s *Server) RunCollector(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	semaphore := make(chan struct{}, 4)
	lastPrune := time.Now().Add(-24 * time.Hour)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		hosts, err := s.store.ListHosts()
		if err != nil {
			slog.Warn("collector: list hosts", "error", err)
			continue
		}
		fleetSettings, _ := s.store.ListSettings("fleet")
		now := time.Now()
		for _, host := range hosts {
			// Scheduled collection is key-only and requires a pinned host key.
			// Password-auth hosts remain manual, where the UI can prompt.
			if host.AuthType != "key" {
				continue
			}
			if key, _ := s.store.GetHostKey(host.ID); key == nil {
				continue
			}
			s.collectorMu.Lock()
			state := s.collectorState[host.ID]
			if state == nil {
				state = &collectorHostState{
					nextMetrics: now.Add(jitter(15*time.Second, 75*time.Second)),
					nextFacts:   now.Add(jitter(30*time.Second, 5*time.Minute)),
				}
				s.collectorState[host.ID] = state
			}
			if now.Sub(state.settingsLoaded) >= time.Minute {
				hostSettings, _ := s.store.ListSettings("host:" + host.ID)
				merged := mergeSettings(settingDefaults, fleetSettings, hostSettings)
				state.enabled = merged["collector.enabled"] == "1"
				state.metricsInterval = durationSetting(merged["collector.metrics_interval"], 5*time.Minute)
				state.factsInterval = durationSetting(merged["collector.facts_interval"], 12*time.Hour)
				state.retentionDays = intSetting(merged["metrics.retention_days"], 30)
				state.settingsLoaded = now
			}
			if !state.enabled {
				s.collectorMu.Unlock()
				continue
			}
			runMetrics := !state.metricsRunning && !now.Before(state.nextMetrics)
			if runMetrics {
				state.metricsRunning = true
				state.nextMetrics = now.Add(state.metricsInterval)
			}
			runFacts := !state.factsRunning && !now.Before(state.nextFacts)
			if runFacts {
				state.factsRunning = true
				state.nextFacts = now.Add(state.factsInterval)
			}
			s.collectorMu.Unlock()

			if runMetrics {
				go func(host store.Host, state *collectorHostState) {
					semaphore <- struct{}{}
					defer func() { <-semaphore }()
					defer func() {
						s.collectorMu.Lock()
						state.metricsRunning = false
						s.collectorMu.Unlock()
					}()
					s.scheduledMetrics(ctx, host)
				}(host, state)
			}
			if runFacts {
				go func(host store.Host, state *collectorHostState) {
					semaphore <- struct{}{}
					defer func() { <-semaphore }()
					defer func() {
						s.collectorMu.Lock()
						state.factsRunning = false
						s.collectorMu.Unlock()
					}()
					s.scheduledFacts(ctx, host)
				}(host, state)
			}
		}
		if now.Sub(lastPrune) >= 24*time.Hour {
			s.pruneMetrics(hosts)
			lastPrune = now
		}
	}
}

func (s *Server) scheduledMetrics(ctx context.Context, host store.Host) {
	output, code, err := s.runHelper(ctx, host, "metrics", "", "", 2*time.Minute)
	if err != nil {
		logCollectorError(host, "metrics", err)
		return
	}
	if code != 0 {
		slog.Warn("collector: metrics helper failed", "host", host.Name, "output", strings.TrimSpace(output))
		return
	}
	var metrics helper.Metrics
	if err := json.Unmarshal([]byte(output), &metrics); err != nil {
		slog.Warn("collector: invalid metrics", "host", host.Name, "error", err)
		return
	}
	if metrics.CollectedAt == "" {
		metrics.CollectedAt = crypto.Now()
	}
	if err := s.store.SaveMetrics(host.ID, store.MetricSample{
		CollectedAt: metrics.CollectedAt, CPUPercent: metrics.CPUPercent,
		MemoryPercent: metrics.MemoryPercent, SwapPercent: metrics.SwapPercent,
		DiskPercent: metrics.DiskPercent, Load1: metrics.Load1, Load5: metrics.Load5,
		Load15: metrics.Load15, UptimeSeconds: metrics.UptimeSeconds,
	}); err != nil {
		slog.Warn("collector: save metrics", "host", host.Name, "error", err)
	}
}

func (s *Server) scheduledFacts(ctx context.Context, host store.Host) {
	if output, code, err := s.runHelper(ctx, host, "facts", "", "", 2*time.Minute); err != nil {
		logCollectorError(host, "facts", err)
	} else if code != 0 {
		slog.Warn("collector: facts helper failed", "host", host.Name, "output", strings.TrimSpace(output))
	} else {
		var facts helper.Facts
		if err := json.Unmarshal([]byte(output), &facts); err == nil {
			_ = s.store.SaveFacts(host.ID, storeFactsFromHelper(facts))
		}
	}
	if _, err := s.collectSystemInfo(ctx, host, "", ""); err != nil {
		logCollectorError(host, "system-info", err)
	}
	if _, err := s.collectDockerInventory(ctx, host, "", ""); err != nil {
		logCollectorError(host, "docker-list", err)
	}
}

func (s *Server) pruneMetrics(hosts []store.Host) {
	for _, host := range hosts {
		s.collectorMu.Lock()
		state := s.collectorState[host.ID]
		days := 30
		if state != nil && state.retentionDays > 0 {
			days = state.retentionDays
		}
		s.collectorMu.Unlock()
		cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339Nano)
		if err := s.store.DeleteMetricsBeforeForHost(host.ID, cutoff); err != nil {
			slog.Warn("collector: prune metrics", "host", host.Name, "error", err)
		}
	}
}

func mergeSettings(fallback map[string]string, layers ...map[string]string) map[string]string {
	result := make(map[string]string, len(fallback))
	for key, value := range fallback {
		result[key] = value
	}
	for _, layer := range layers {
		for key, value := range layer {
			if _, ok := result[key]; ok {
				result[key] = value
			}
		}
	}
	return result
}

func durationSetting(value string, fallback time.Duration) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 10*time.Second {
		return fallback
	}
	return duration
}

func intSetting(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > 3650 {
		return fallback
	}
	return parsed
}

func jitter(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int64N(int64(max-min)))
}

func logCollectorError(host store.Host, action string, err error) {
	if errors.Is(err, errSudoPasswordRequired) {
		slog.Debug("collector: passwordless helper required", "host", host.Name, "action", action)
		return
	}
	slog.Warn("collector: helper failed", "host", host.Name, "action", action, "error", err)
}
