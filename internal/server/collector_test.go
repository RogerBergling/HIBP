package server

import (
	"testing"
	"time"
)

func TestCollectorSettingHelpers(t *testing.T) {
	fleet := map[string]string{"collector.metrics_interval": "1m", "collector.enabled": "0"}
	host := map[string]string{"collector.metrics_interval": "10s"}
	merged := mergeSettings(settingDefaults, fleet, host)
	if merged["collector.metrics_interval"] != "10s" {
		t.Fatalf("host setting did not win: %q", merged["collector.metrics_interval"])
	}
	if merged["collector.enabled"] != "0" {
		t.Fatalf("fleet setting did not apply: %q", merged["collector.enabled"])
	}
	if merged["collector.facts_interval"] != "12h" {
		t.Fatalf("default did not apply: %q", merged["collector.facts_interval"])
	}
	if got := durationSetting("10s", 5*time.Minute); got != 10*time.Second {
		t.Fatalf("duration setting rejected: %s", got)
	}
	if got := durationSetting("5s", 5*time.Minute); got != 5*time.Minute {
		t.Fatalf("unsafe duration was not replaced: %s", got)
	}
	if got := intSetting("14", 30); got != 14 {
		t.Fatalf("integer setting rejected: %d", got)
	}
	if got := intSetting("0", 30); got != 30 {
		t.Fatalf("invalid integer was not replaced: %d", got)
	}
}
