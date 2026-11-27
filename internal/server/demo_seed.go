//go:build demo

package server

import (
	"encoding/json"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/store"
)

const demoKeyPath = "/tmp/hibp-demo-ssh/id_ed25519"

// SeedDemo creates the fake guest account, fake fleet, monitoring, schedules,
// jobs, and history used by the public demo. It is safe to call only on a new
// database; existing data is left untouched.
func SeedDemo(st *store.Store) error {
	users, err := st.CountUsers()
	if err != nil {
		return err
	}
	hosts, err := st.CountHosts()
	if err != nil {
		return err
	}
	if users > 0 || hosts > 0 {
		return nil
	}

	hash, err := auth.HashPasswordForDemo(demoPassword)
	if err != nil {
		return err
	}
	user, err := st.CreateUser(demoUsername, hash)
	if err != nil {
		return err
	}
	if err := st.EnableTOTP(user.ID, demoTOTPSecret, 0); err != nil {
		return err
	}
	_ = st.AddAudit(demoUsername, "demo-seed", "system", "", "Public demo initialized")

	runtime := &demoRuntime{
		store:   st,
		patched: map[string]bool{},
		cleaned: map[string]bool{},
		reboot:  map[string]bool{},
	}
	type sample struct {
		host    store.Host
		facts   store.Facts
		trusted bool
		docker  bool
	}
	samples := []sample{
		{
			host:    store.Host{Name: "web01", Address: "10.20.0.11", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: demoKeyPath, Tags: "web,prod", GroupName: "web-prod", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 41 * 86400, Kernel: "6.8.0-51-generic", OSPrettyName: "Ubuntu 24.04 LTS", PackageManager: "apt", PendingUpdates: 4, OrphanedPackages: 2, CleanupSupported: true, RebootRequired: true, DiskFreeBytes: 42 << 30, TimeSyncOK: true},
			trusted: true, docker: true,
		},
		{
			host:    store.Host{Name: "web02", Address: "10.20.0.12", Port: 22, Username: "ubuntu", AuthType: "key", KeyPath: demoKeyPath, Tags: "web,staging", GroupName: "web-staging", Status: "unknown"},
			facts:   store.Facts{UptimeSeconds: 2 * 86400, Kernel: "6.8.0-45-generic", OSPrettyName: "Ubuntu 22.04 LTS", PackageManager: "apt", PendingUpdates: 3, OrphanedPackages: 1, CleanupSupported: true, DiskFreeBytes: 55 << 30, TimeSyncOK: true},
			trusted: false,
		},
		{
			host:    store.Host{Name: "db01", Address: "10.20.0.21", Port: 22, Username: "root", AuthType: "key", KeyPath: demoKeyPath, Tags: "db,prod", GroupName: "db-prod", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 112 * 86400, Kernel: "6.1.0-34-amd64", OSPrettyName: "Debian 12", PackageManager: "apt", PendingUpdates: 0, DiskFreeBytes: 80 << 30, TimeSyncOK: true},
			trusted: true,
		},
		{
			host:    store.Host{Name: "docker01", Address: "10.20.0.31", Port: 22, Username: "docker", AuthType: "key", KeyPath: demoKeyPath, Tags: "docker,prod", GroupName: "containers", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 18 * 86400, Kernel: "6.8.0-51-generic", OSPrettyName: "Ubuntu 24.04 LTS", PackageManager: "apt", PendingUpdates: 5, OrphanedPackages: 1, CleanupSupported: true, RebootRequired: true, DiskFreeBytes: 120 << 30, TimeSyncOK: true},
			trusted: true, docker: true,
		},
		{
			host:    store.Host{Name: "fedora01", Address: "10.20.0.41", Port: 22, Username: "fedora", AuthType: "key", KeyPath: demoKeyPath, Tags: "web,prod", GroupName: "web-prod", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 12 * 86400, Kernel: "6.12.4", OSPrettyName: "Fedora 41", PackageManager: "dnf", PendingUpdates: 7, OrphanedPackages: 3, CleanupSupported: true, RebootRequired: true, DiskFreeBytes: 35 << 30, TimeSyncOK: true},
			trusted: true,
		},
		{
			host:    store.Host{Name: "kali-lab", Address: "10.20.0.51", Port: 22, Username: "kali", AuthType: "key", KeyPath: demoKeyPath, Tags: "lab,security", GroupName: "lab", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 3 * 86400, Kernel: "6.12.9", OSPrettyName: "Kali GNU/Linux 2026.1", PackageManager: "apt", PendingUpdates: 2, OrphanedPackages: 1, CleanupSupported: true, DiskFreeBytes: 18 << 30, TimeSyncOK: false},
			trusted: true,
		},
		{
			host:    store.Host{Name: "suse01", Address: "10.20.0.61", Port: 22, Username: "root", AuthType: "key", KeyPath: demoKeyPath, Tags: "db,prod", GroupName: "db-prod", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 27 * 86400, Kernel: "6.4.0", OSPrettyName: "openSUSE Leap 15.6", PackageManager: "zypper", PendingUpdates: 1, DiskFreeBytes: 60 << 30, TimeSyncOK: true},
			trusted: true,
		},
		{
			host:    store.Host{Name: "arch01", Address: "10.20.0.71", Port: 22, Username: "roger", AuthType: "key", KeyPath: demoKeyPath, Tags: "lab,desktop", GroupName: "lab", Status: "reachable"},
			facts:   store.Facts{UptimeSeconds: 8 * 86400, Kernel: "6.13.1", OSPrettyName: "Arch Linux", PackageManager: "pacman", PendingUpdates: 0, DiskFreeBytes: 25 << 30, TimeSyncOK: true},
			trusted: true,
		},
	}

	created := make([]store.Host, 0, len(samples))
	for _, entry := range samples {
		host, err := st.CreateHost(entry.host)
		if err != nil {
			return err
		}
		if entry.trusted {
			if err := st.SaveHostKeyAs("demo", store.HostKey{
				HostID: host.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:demo-" + shortDemoName(host.Name),
			}); err != nil {
				return err
			}
		}
		facts := entry.facts
		facts.CollectedAt = time.Now().UTC().Format(time.RFC3339)
		facts.BootTime = time.Now().UTC().Add(-time.Duration(facts.UptimeSeconds) * time.Second).Format(time.RFC3339)
		facts.Agent = buildinfo.Current
		if err := st.SaveFactsAs("demo", host.ID, facts); err != nil {
			return err
		}
		host.Facts = &facts
		created = append(created, host)

		info := runtime.systemInfo(host)
		payload, err := json.Marshal(info)
		if err != nil {
			return err
		}
		if err := st.SaveSystemInfo(host.ID, info.CollectedAt, string(payload)); err != nil {
			return err
		}
		if err := st.SaveServiceState(host.ID, info.Systemd.FailedUnits, info.Systemd.RunningUnits); err != nil {
			return err
		}
		if err := st.EnsureServiceBaseline(host.ID, info.Systemd.RunningUnits); err != nil {
			return err
		}
		for i := 0; i < 96; i++ {
			sample := runtime.metrics(host)
			if err := st.SaveMetrics(host.ID, store.MetricSample{
				CollectedAt: time.Now().UTC().Add(-time.Duration(i) * 15 * time.Minute).Format(time.RFC3339Nano),
				CPUPercent:  sample.CPUPercent, MemoryPercent: sample.MemoryPercent,
				SwapPercent: sample.SwapPercent, DiskPercent: sample.DiskPercent,
				Load1: sample.Load1, Load5: sample.Load5, Load15: sample.Load15,
				UptimeSeconds: sample.UptimeSeconds,
			}); err != nil {
				return err
			}
		}
		if entry.docker {
			inventory := runtime.dockerInventory(host)
			projects := make([]store.DockerProject, 0, len(inventory.Projects))
			for _, project := range inventory.Projects {
				projects = append(projects, store.DockerProject{
					HostID: host.ID, Name: project.Name, Status: project.Status,
					ConfigFiles: project.ConfigFiles, WorkingDir: project.WorkingDir,
					LastSeen: inventory.CollectedAt,
				})
			}
			containers := make([]store.DockerContainer, 0, len(inventory.Containers))
			for _, container := range inventory.Containers {
				containers = append(containers, store.DockerContainer{
					HostID: host.ID, ContainerID: container.ID, Name: container.Name,
					Project: container.Project, Service: container.Service, Image: container.Image,
					State: container.State, Status: container.Status, Health: container.Health,
					Ports: container.Ports, CreatedAt: container.CreatedAt, LastSeen: inventory.CollectedAt,
				})
			}
			if err := st.SaveDockerInventory(host.ID, projects, containers); err != nil {
				return err
			}
			if err := st.SaveDockerProjectCheck(store.DockerProjectCheck{
				HostID: host.ID, Project: "app", Status: "update-available",
				CheckedAt: inventory.CollectedAt, Summary: "web: new image available",
			}); err != nil {
				return err
			}
			if err := st.SaveDockerProjectCheck(store.DockerProjectCheck{
				HostID: host.ID, Project: "monitoring", Status: "up-to-date",
				CheckedAt: inventory.CollectedAt, Summary: "all services current",
			}); err != nil {
				return err
			}
		}
	}

	settings := map[string]string{
		"collector.enabled":          "1",
		"collector.metrics_interval": "2m",
		"collector.facts_interval":   "30m",
		"metrics.retention_days":     "30",
	}
	for key, value := range settings {
		if err := st.SetSetting("fleet", key, value); err != nil {
			return err
		}
	}
	smtp := map[string]string{
		"enabled":         "1",
		"host":            "demo-smtp.invalid",
		"port":            "25",
		"mode":            "none",
		"from":            "hibp-demo@example.invalid",
		"recipients":      "demo@example.invalid",
		"timeout_seconds": "15",
	}
	for key, value := range smtp {
		if err := st.SetSetting("smtp", key, value); err != nil {
			return err
		}
	}

	hostsByID := map[string]store.Host{}
	for _, host := range created {
		hostsByID[host.ID] = host
	}

	monitors := []store.Monitor{
		{
			Name: "Public web service (demo)", Type: "http", Target: "https://demo.example.invalid/health",
			IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		},
		{
			Name: "Database TCP port (demo)", Type: "tcp", Target: "db01.demo.invalid:5432",
			IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
		},
		{
			Name: "TLS certificate (demo)", Type: "ssl", Target: "demo.example.invalid:443",
			Warning: 30, Critical: 14, IntervalSeconds: 300, RepeatMinutes: 1440, CooldownMinutes: 60, Enabled: true,
		},
		{
			Name: "Fleet CPU (demo)", Type: "host.cpu", Warning: 80, Critical: 90,
			IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
			Assignments: []store.MonitorAssignment{{Scope: "fleet"}},
		},
		{
			Name: "app Compose project (demo)", Type: "docker.project", Target: "app",
			IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
			Assignments: []store.MonitorAssignment{{Scope: "host", Target: created[0].ID}},
		},
		{
			Name: "nginx.service on web01 (demo)", Type: "service.systemd", Target: "nginx.service",
			IntervalSeconds: 60, RepeatMinutes: 60, CooldownMinutes: 15, Enabled: true,
			Assignments: []store.MonitorAssignment{{Scope: "host", Target: created[0].ID}},
		},
	}
	createdMonitors := make([]store.Monitor, 0, len(monitors))
	for _, monitor := range monitors {
		saved, err := st.CreateMonitor(monitor)
		if err != nil {
			return err
		}
		createdMonitors = append(createdMonitors, saved)
	}
	now := time.Now().UTC()
	for _, monitor := range createdMonitors {
		switch monitor.Type {
		case "http":
			_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: "", Status: "ok", Message: "HTTP 200 in 42ms (demo)", CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)})
		case "tcp":
			_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: "", Status: "ok", Message: "TCP connect 8ms (demo)", CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)})
		case "ssl":
			_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: "", Status: "ok", Message: "certificate expires in 120.0 days (demo)", CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)})
		case "host.cpu":
			for _, host := range created {
				status := "ok"
				message := "CPU 18.4%"
				if host.Name == "fedora01" {
					status = "warning"
					message = "CPU 84.2% (demo warning)"
				}
				_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: host.ID, Status: status, Message: message, CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-30 * time.Minute).Format(time.RFC3339Nano)})
			}
		case "docker.project":
			_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: created[0].ID, Status: "ok", Message: "2/2 containers running (demo)", CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-20 * time.Minute).Format(time.RFC3339Nano)})
		case "service.systemd":
			_ = st.UpsertMonitorState(store.MonitorState{MonitorID: monitor.ID, HostID: created[0].ID, Status: "critical", Message: "service is failed (demo)", CheckedAt: now.Format(time.RFC3339Nano), ChangedAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano)})
		}
		_ = st.SetMonitorChecked(monitor.ID, now.Format(time.RFC3339Nano))
	}
	if len(createdMonitors) > 0 {
		_ = st.AddAlertEvent(store.AlertEvent{
			MonitorID: createdMonitors[0].ID, Status: "ok", Subject: "Public web service (demo) recovered",
			Detail: "HTTP 200 in 42ms (demo)", CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339Nano), Emailed: true,
		})
		_ = st.AddAlertEvent(store.AlertEvent{
			MonitorID: createdMonitors[5].ID, HostID: created[0].ID, Status: "critical",
			Subject: "nginx.service on web01 (demo) is failed",
			Detail:  "service is failed (demo)", CreatedAt: now.Add(-10 * time.Minute).Format(time.RFC3339Nano), Emailed: true,
		})
	}

	checkSchedule, err := st.CreateSchedule(store.Schedule{
		Name: "Nightly fleet check (demo)", Mode: "check", Enabled: true,
		Cron: "*/15 * * * *", Timezone: "UTC", WindowMinutes: 120,
		JitterSeconds: 15, MaxConcurrency: 3, Retries: 1, Notify: "failures",
		Assignments: []store.ScheduleAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		return err
	}
	applySchedule, err := st.CreateSchedule(store.Schedule{
		Name: "Weekly production apply (demo)", Mode: "apply", Enabled: true,
		Cron: "0 3 * * 0", Timezone: "UTC", WindowMinutes: 240,
		JitterSeconds: 60, MaxConcurrency: 2, Retries: 1, Notify: "always",
		RebootAfterApply: true, Assignments: []store.ScheduleAssignment{{Scope: "fleet"}},
	})
	if err != nil {
		return err
	}
	for index, host := range created[:3] {
		started := now.Add(-time.Duration(index+1) * time.Hour).Format(time.RFC3339Nano)
		run, err := st.StartRun(store.Run{
			ScheduleID: checkSchedule.ID, HostID: host.ID, Action: "patch-check",
			StartedAt: started, Status: "running",
		})
		if err != nil {
			return err
		}
		_ = st.FinishRun(run.ID, "success", 0, "demo: 4 updates available", "", now.Add(-time.Duration(index+1)*time.Hour+time.Minute).Format(time.RFC3339Nano))
	}
	_ = st.SetScheduleResult(checkSchedule.ID, "success", "3 succeeded, 0 failed, 0 skipped (demo)")
	_ = st.SetScheduleResult(applySchedule.ID, "success", "simulated weekly apply (demo)")

	previewTargets := []store.JobTarget{
		{HostID: created[0].ID, HostName: created[0].Name, Status: store.JobTargetPending},
		{HostID: created[4].ID, HostName: created[4].Name, Status: store.JobTargetPending},
	}
	previewJob, err := st.CreateJob(store.Job{
		Kind: "patch-preview", Status: store.JobSucceeded, Actor: demoUsername,
		Title: "Patch preview for 2 hosts", Detail: "2 ready · 0 failed · 0 skipped", Payload: "{}",
	}, previewTargets)
	if err != nil {
		return err
	}
	for _, target := range previewTargets {
		host := hostsByID[target.HostID]
		preview := runtime.preview(host)
		result, _ := json.Marshal(map[string]any{"preview": preview, "preview_hash": previewHash(preview)})
		_ = st.FinishJobTarget(store.JobTarget{
			JobID: previewJob.ID, HostID: target.HostID, Status: store.JobTargetSucceeded,
			Stage: "done", Detail: "demo package changes", Result: string(result),
		})
	}
	_ = st.FinishJob(previewJob.ID, store.JobSucceeded, "2 ready · 0 failed · 0 skipped")

	pkgPayload, _ := json.Marshal(jobPayload{Package: &jobPackageSpec{
		Name: "wazuh-agent_4.7.5-1_amd64.deb", SHA256: "demo", Size: 12 << 20,
		Env: map[string]string{"WAZUH_MANAGER": "10.20.0.5"},
	}})
	packageJob, err := st.CreateJob(store.Job{
		Kind: "package-install", Status: store.JobSucceeded, Actor: demoUsername,
		Title:  "Install wazuh-agent_4.7.5-1_amd64.deb on 1 host",
		Detail: "Succeeded 1 · failed 0 · skipped 0", Payload: string(pkgPayload),
	}, []store.JobTarget{{HostID: created[2].ID, HostName: created[2].Name, Status: store.JobTargetPending}})
	if err != nil {
		return err
	}
	_ = st.FinishJobTarget(store.JobTarget{
		JobID: packageJob.ID, HostID: created[2].ID, Status: store.JobTargetSucceeded,
		Stage: "done", Detail: "installed wazuh-agent_4.7.5-1_amd64.deb",
		Result: `{"install":{"ok":true,"package":"wazuh-agent_4.7.5-1_amd64.deb"},"facts":null}`,
	})
	_ = st.FinishJob(packageJob.ID, store.JobSucceeded, "Succeeded 1 · failed 0 · skipped 0")

	_, err = st.CreateJob(store.Job{
		Kind: "facts", Status: store.JobQueued, Actor: demoUsername,
		Title: "Collect facts from 1 host", Detail: "Queued", Payload: "{}",
	}, []store.JobTarget{{HostID: created[3].ID, HostName: created[3].Name, Status: store.JobTargetPending}})
	if err != nil {
		return err
	}

	_ = st.AddAudit(demoUsername, "demo-data", "system", "", "Fake fleet, monitoring, schedules, and jobs seeded")
	return nil
}
