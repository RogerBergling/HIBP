package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// pollVCenter reads active alarm states from all managed entities. It never
// creates, acknowledges, clears, or otherwise changes vCenter objects.
func (s *Server) pollVCenter(ctx context.Context, cfg integrationConfig) (integrationPollResult, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return integrationPollResult{}, err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/sdk"
	}
	u.User = url.UserPassword(cfg.Username, cfg.Password)
	client, err := govmomi.NewClient(ctx, u, cfg.Insecure)
	if err != nil {
		return integrationPollResult{}, fmt.Errorf("vCenter login: %w", err)
	}
	defer func() {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Logout(logoutCtx)
	}()

	manager := view.NewManager(client.Client)
	container, err := manager.CreateContainerView(ctx, client.ServiceContent.RootFolder, []string{"ManagedEntity"}, true)
	if err != nil {
		return integrationPollResult{}, fmt.Errorf("vCenter inventory view: %w", err)
	}
	defer func() {
		destroyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = container.Destroy(destroyCtx)
	}()
	var entities []mo.ManagedEntity
	if err := container.Retrieve(ctx, []string{"ManagedEntity"}, []string{"name", "triggeredAlarmState"}, &entities); err != nil {
		return integrationPollResult{}, fmt.Errorf("vCenter alarm inventory: %w", err)
	}

	alarmRefs := make(map[string]types.ManagedObjectReference)
	for _, entity := range entities {
		for _, state := range entity.TriggeredAlarmState {
			if state.OverallStatus == types.ManagedEntityStatusGreen || state.OverallStatus == types.ManagedEntityStatusGray {
				continue
			}
			if state.Disabled != nil && *state.Disabled {
				continue
			}
			if state.Alarm.Value != "" {
				alarmRefs[state.Alarm.Value] = state.Alarm
			}
		}
	}
	alarmNames := make(map[string]string, len(alarmRefs))
	if len(alarmRefs) > 0 {
		refs := make([]types.ManagedObjectReference, 0, len(alarmRefs))
		for _, ref := range alarmRefs {
			refs = append(refs, ref)
		}
		var alarms []mo.Alarm
		if err := property.DefaultCollector(client.Client).Retrieve(ctx, refs, []string{"info"}, &alarms); err != nil {
			return integrationPollResult{}, fmt.Errorf("vCenter alarm names: %w", err)
		}
		for _, alarm := range alarms {
			alarmNames[alarm.Self.Value] = alarm.Info.Name
		}
	}

	var findings []integrationFinding
	for _, entity := range entities {
		entityName := strings.TrimSpace(entity.Name)
		if entityName == "" {
			entityName = entity.Self.Value
		}
		for _, state := range entity.TriggeredAlarmState {
			if state.OverallStatus == types.ManagedEntityStatusGreen || state.OverallStatus == types.ManagedEntityStatusGray {
				continue
			}
			if state.Disabled != nil && *state.Disabled {
				continue
			}
			severity := "warning"
			if state.OverallStatus == types.ManagedEntityStatusRed {
				severity = "critical"
			}
			alarmName := alarmNames[state.Alarm.Value]
			if alarmName == "" {
				alarmName = state.Alarm.Value
			}
			acknowledged := false
			if state.Acknowledged != nil {
				acknowledged = *state.Acknowledged
			}
			triggered := ""
			if !state.Time.IsZero() {
				triggered = state.Time.UTC().Format(time.RFC3339)
			}
			detail := fmt.Sprintf("alarm=%s, entity=%s, overallStatus=%s, triggered=%s, acknowledged=%t",
				alarmName, entityName, state.OverallStatus, triggered, acknowledged)
			action := "triggered"
			if severity == "warning" {
				action = "warning"
			}
			findings = append(findings, integrationFinding{
				Key:     state.Alarm.Value + ":" + state.Entity.Value,
				Status:  severity,
				Subject: fmt.Sprintf("vCenter alarm %s - %s on %s", action, alarmName, entityName),
				Detail:  detail,
			})
		}
	}
	return integrationPollResult{
		Summary:  fmt.Sprintf("%d managed entities, %d active alarms", len(entities), len(findings)),
		Findings: findings,
	}, nil
}
