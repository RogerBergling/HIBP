//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"time"
)

func collect(ctx context.Context) (*agentSnapshot, json.RawMessage, error) {
	snapshot := &agentSnapshot{}
	if output, err := powershell(ctx, `$os=Get-CimInstance Win32_OperatingSystem; $w=(w32tm /query /status 2>$null) -join ' '; [pscustomobject]@{os_pretty_name=$os.Caption; kernel=$os.Version; uptime_seconds=[int]((Get-Date)-$os.LastBootUpTime).TotalSeconds; time_sync_ok=($w -match 'Source:' -and $w -notmatch 'Local CMOS Clock'); time_sync_source=$(if($w){'w32time'}else{''}); time_sync_offset_known=$false} | ConvertTo-Json -Compress`); err == nil {
		snapshot.Facts = json.RawMessage(bytes.TrimSpace(output))
	}
	if output, err := powershell(ctx, `Get-Service | Select-Object Name,Status | ConvertTo-Json -Compress`); err == nil {
		var services []struct {
			Name   string `json:"Name"`
			Status string `json:"Status"`
		}
		if json.Unmarshal(output, &services) == nil {
			running := make([]string, 0, len(services))
			for _, service := range services {
				if strings.EqualFold(service.Status, "Running") {
					running = append(running, service.Name)
				}
			}
			snapshot.Services = &agentServices{Running: running, Failed: []string{}}
		}
	}
	events := collectWindowsEvents(ctx)
	return snapshot, events, nil
}

func collectWindowsEvents(ctx context.Context) json.RawMessage {
	script := `$start=(Get-Date).AddMinutes(-15); $result=@(); $result += Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$start} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{event_id="security-4625-$($_.RecordId)";source='Security/4625';category='auth_failure';severity='warning';message=$_.Message;occurred_at=$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')} }; $result += Get-WinEvent -FilterHashtable @{LogName='System';Id=7031,7034;StartTime=$start} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{event_id="system-$($_.Id)-$($_.RecordId)";source='System';category='service_failure';severity='critical';message=$_.Message;occurred_at=$_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')} }; $result | ConvertTo-Json -Compress`
	output, err := powershell(ctx, script)
	if err != nil || len(bytes.TrimSpace(output)) == 0 {
		return nil
	}
	output = bytes.TrimSpace(output)
	if bytes.Equal(output, []byte("null")) {
		return nil
	}
	if output[0] == '{' {
		output = append(append([]byte("["), output...), ']')
	}
	var events []struct {
		EventID    string `json:"event_id"`
		Source     string `json:"source"`
		Category   string `json:"category"`
		Severity   string `json:"severity"`
		Message    string `json:"message"`
		OccurredAt string `json:"occurred_at"`
	}
	if json.Unmarshal(output, &events) != nil {
		return nil
	}
	for index := range events {
		if events[index].OccurredAt == "" {
			events[index].OccurredAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if len(events[index].Message) > 512 {
			events[index].Message = events[index].Message[:512]
		}
	}
	raw, _ := json.Marshal(events)
	return raw
}

func powershell(ctx context.Context, script string) ([]byte, error) {
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return command.Output()
}
