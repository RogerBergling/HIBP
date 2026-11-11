package store

import (
	"database/sql"
	"errors"
	"testing"
)

func TestScheduleAndRunLifecycle(t *testing.T) {
	s := openAuthTestStore(t)
	host, err := s.CreateHost(Host{
		Name: "web01", Address: "10.0.0.10", Port: 22, Username: "ubuntu",
		AuthType: "key", KeyPath: "/home/ops/.ssh/id_ed25519",
	})
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := s.CreateSchedule(Schedule{
		Name: "Nightly patches", Mode: "apply", Enabled: true, Cron: "0 3 * * *",
		Timezone: "UTC", WindowMinutes: 120, JitterSeconds: 60, MaxConcurrency: 3,
		Retries: 2, Notify: "failures", Assignments: []ScheduleAssignment{{Scope: "host", Target: host.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if schedule.ID == "" || schedule.LastRunAt == "" || schedule.CreatedAt == "" {
		t.Fatalf("unexpected created schedule: %+v", schedule)
	}
	assignments, err := s.ListScheduleAssignments(schedule.ID)
	if err != nil || len(assignments) != 1 || assignments[0].Target != host.ID {
		t.Fatalf("assignments: %+v %v", assignments, err)
	}
	schedule.Name = "Nightly patches updated"
	schedule.Assignments = []ScheduleAssignment{{Scope: "fleet"}}
	if err := s.UpdateSchedule(schedule); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetSchedule(schedule.ID)
	if err != nil || loaded.Name != schedule.Name || !loaded.Enabled {
		t.Fatalf("loaded schedule: %+v %v", loaded, err)
	}
	if loaded.Retries != 2 {
		t.Fatalf("loaded retries = %d, want 2", loaded.Retries)
	}
	assignments, _ = s.ListScheduleAssignments(schedule.ID)
	if len(assignments) != 1 || assignments[0].Scope != "fleet" {
		t.Fatalf("updated assignments: %+v", assignments)
	}
	if err := s.SetScheduleLastRunAt(schedule.ID, "2026-11-11T03:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetScheduleResult(schedule.ID, "failed", "1 failed"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = s.GetSchedule(schedule.ID)
	if loaded.LastStatus != "failed" || loaded.LastSummary != "1 failed" {
		t.Fatalf("schedule result: %+v", loaded)
	}

	run, err := s.StartRun(Run{ScheduleID: schedule.ID, HostID: host.ID, Action: "patch-apply"})
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || run.StartedAt == "" || run.Status != "running" {
		t.Fatalf("started run: %+v", run)
	}
	if err := s.FinishRun(run.ID, "success", 0, "upgraded 3 packages", "", "2026-11-11T03:01:00Z"); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListRuns(10, schedule.ID, host.ID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs: %+v %v", runs, err)
	}
	if runs[0].Status != "success" || runs[0].ExitCode != 0 || runs[0].Output != "upgraded 3 packages" {
		t.Fatalf("unexpected run: %+v", runs[0])
	}
	if err := s.DeleteSchedule(schedule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSchedule(schedule.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected deleted schedule, got %v", err)
	}
}
