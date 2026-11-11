package store

import (
	"testing"
)

func TestObservabilitySnapshotsAndSettings(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSystemInfo(host.ID, "2026-11-11T07:00:00Z", `{"hostname":"web01"}`); err != nil {
		t.Fatal(err)
	}
	info, err := s.GetSystemInfo(host.ID)
	if err != nil || info.PayloadJSON == "" {
		t.Fatalf("system info: %+v %v", info, err)
	}
	if err := s.SaveMetrics(host.ID, MetricSample{CollectedAt: "2026-11-11T07:00:00Z", CPUPercent: 10, MemoryPercent: 20, DiskPercent: 30}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveMetrics(host.ID, MetricSample{CollectedAt: "2026-11-11T07:05:00Z", CPUPercent: 50, MemoryPercent: 25, DiskPercent: 31}); err != nil {
		t.Fatal(err)
	}
	metrics, err := s.ListMetrics(host.ID, 10)
	if err != nil || len(metrics) != 2 {
		t.Fatalf("metrics: %+v %v", metrics, err)
	}
	if metrics[0].CPUPercent != 10 || metrics[1].CPUPercent != 50 {
		t.Fatalf("metrics not oldest-first: %+v", metrics)
	}

	if err := s.SaveDockerInventory(host.ID,
		[]DockerProject{{Name: "web", Status: "running(2)", ConfigFiles: "/opt/web/compose.yaml", WorkingDir: "/opt/web"}},
		[]DockerContainer{{ContainerID: "abc", Name: "web-1", Project: "web", Service: "frontend", Image: "nginx", State: "running", Health: "healthy"}}); err != nil {
		t.Fatal(err)
	}
	projects, containers, err := s.GetDockerInventory(host.ID)
	if err != nil || len(projects) != 1 || len(containers) != 1 {
		t.Fatalf("docker inventory: %+v %+v %v", projects, containers, err)
	}
	if projects[0].Name != "web" || containers[0].Health != "healthy" {
		t.Fatalf("unexpected docker inventory: %+v %+v", projects, containers)
	}

	if err := s.SetSetting("fleet", "collector.metrics_interval", "5m"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("host:"+host.ID, "collector.metrics_interval", "1m"); err != nil {
		t.Fatal(err)
	}
	if got := s.ResolveSetting(host.ID, "collector.metrics_interval", "10m"); got != "1m" {
		t.Fatalf("host override not applied: %q", got)
	}
	if got := s.ResolveSetting("other", "collector.metrics_interval", "10m"); got != "5m" {
		t.Fatalf("fleet default not applied: %q", got)
	}
	if err := s.DeleteSetting("host:"+host.ID, "collector.metrics_interval"); err != nil {
		t.Fatal(err)
	}
	if got := s.ResolveSetting(host.ID, "collector.metrics_interval", "10m"); got != "5m" {
		t.Fatalf("fleet default not applied after delete: %q", got)
	}
}
