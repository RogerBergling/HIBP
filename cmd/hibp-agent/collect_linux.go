//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/RogerBergling/hibp/internal/helper"
)

func collect(ctx context.Context) (*agentSnapshot, json.RawMessage, error) {
	var facts bytes.Buffer
	if err := helper.Run(ctx, "facts", &facts); err != nil {
		return nil, nil, err
	}
	var metrics bytes.Buffer
	snapshot := &agentSnapshot{Facts: json.RawMessage(bytes.TrimSpace(facts.Bytes()))}
	if err := helper.Run(ctx, "metrics", &metrics); err == nil {
		var value struct {
			RunningUnits []string `json:"running_units"`
			FailedUnits  []string `json:"failed_units"`
		}
		if json.Unmarshal(metrics.Bytes(), &value) == nil {
			snapshot.Services = &agentServices{Running: value.RunningUnits, Failed: value.FailedUnits}
		}
	}
	var docker bytes.Buffer
	if err := helper.Run(ctx, "docker-list", &docker); err == nil {
		snapshot.Docker = json.RawMessage(bytes.TrimSpace(docker.Bytes()))
	}
	var events bytes.Buffer
	if err := helper.Run(ctx, "events", &events); err == nil {
		return snapshot, json.RawMessage(bytes.TrimSpace(events.Bytes())), nil
	}
	return snapshot, nil, nil
}
