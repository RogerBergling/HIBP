package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

type Schedule struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Mode           string               `json:"mode"`
	Enabled        bool                 `json:"enabled"`
	Cron           string               `json:"cron"`
	Timezone       string               `json:"timezone"`
	WindowMinutes  int                  `json:"window_minutes"`
	JitterSeconds  int                  `json:"jitter_seconds"`
	MaxConcurrency int                  `json:"max_concurrency"`
	RunIfMissed    bool                 `json:"run_if_missed"`
	Notify         string               `json:"notify"`
	Recipients     string               `json:"recipients"`
	LastRunAt      string               `json:"last_run_at"`
	LastStatus     string               `json:"last_status"`
	LastSummary    string               `json:"last_summary"`
	CreatedAt      string               `json:"created_at"`
	UpdatedAt      string               `json:"updated_at"`
	Assignments    []ScheduleAssignment `json:"assignments,omitempty"`
	NextRunAt      string               `json:"next_run_at,omitempty"`
}

type ScheduleAssignment struct {
	ScheduleID string `json:"schedule_id"`
	Scope      string `json:"scope"`
	Target     string `json:"target"`
}

type Run struct {
	ID         string `json:"id"`
	ScheduleID string `json:"schedule_id"`
	HostID     string `json:"host_id"`
	Action     string `json:"action"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Error      string `json:"error"`
}

func (s *Store) CreateSchedule(schedule Schedule) (Schedule, error) {
	schedule.Name = strings.TrimSpace(schedule.Name)
	if schedule.Name == "" || schedule.Mode == "" || schedule.Cron == "" {
		return Schedule{}, errors.New("schedule name, mode, and cron are required")
	}
	schedule.ID = uuid.NewString()
	now := crypto.Now()
	schedule.CreatedAt = now
	schedule.UpdatedAt = now
	schedule.LastRunAt = now
	for index := range schedule.Assignments {
		schedule.Assignments[index].ScheduleID = schedule.ID
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Schedule{}, err
	}
	enabled := 0
	if schedule.Enabled {
		enabled = 1
	}
	missed := 0
	if schedule.RunIfMissed {
		missed = 1
	}
	_, err = tx.Exec(`INSERT INTO schedules(id,name,mode,enabled,cron,timezone,window_minutes,jitter_seconds,
		max_concurrency,run_if_missed,notify,recipients,last_run_at,last_status,last_summary,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		schedule.ID, schedule.Name, schedule.Mode, enabled, schedule.Cron, schedule.Timezone,
		schedule.WindowMinutes, schedule.JitterSeconds, schedule.MaxConcurrency, missed,
		schedule.Notify, schedule.Recipients, now, "", "", now, now)
	if err != nil {
		_ = tx.Rollback()
		return Schedule{}, err
	}
	if err := insertScheduleAssignments(tx, schedule.ID, schedule.Assignments); err != nil {
		_ = tx.Rollback()
		return Schedule{}, err
	}
	if err := tx.Commit(); err != nil {
		return Schedule{}, err
	}
	return schedule, nil
}

func (s *Store) UpdateSchedule(schedule Schedule) error {
	schedule.Name = strings.TrimSpace(schedule.Name)
	if schedule.ID == "" || schedule.Name == "" || schedule.Mode == "" || schedule.Cron == "" {
		return errors.New("schedule id, name, mode, and cron are required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	enabled := 0
	if schedule.Enabled {
		enabled = 1
	}
	missed := 0
	if schedule.RunIfMissed {
		missed = 1
	}
	now := crypto.Now()
	res, err := tx.Exec(`UPDATE schedules SET name=?,mode=?,enabled=?,cron=?,timezone=?,window_minutes=?,
		jitter_seconds=?,max_concurrency=?,run_if_missed=?,notify=?,recipients=?,updated_at=? WHERE id=?`,
		schedule.Name, schedule.Mode, enabled, schedule.Cron, schedule.Timezone, schedule.WindowMinutes,
		schedule.JitterSeconds, schedule.MaxConcurrency, missed, schedule.Notify, schedule.Recipients, now, schedule.ID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		_ = tx.Rollback()
		return sql.ErrNoRows
	}
	if _, err := tx.Exec("DELETE FROM schedule_assignments WHERE schedule_id=?", schedule.ID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := insertScheduleAssignments(tx, schedule.ID, schedule.Assignments); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func insertScheduleAssignments(tx *sql.Tx, scheduleID string, assignments []ScheduleAssignment) error {
	seen := make(map[string]bool)
	for _, assignment := range assignments {
		scope := strings.TrimSpace(assignment.Scope)
		target := strings.TrimSpace(assignment.Target)
		if scope == "" {
			continue
		}
		if scope == "fleet" {
			target = ""
		}
		if scope != "fleet" && target == "" {
			return errors.New("non-fleet schedule assignment requires a target")
		}
		key := scope + "\x00" + target
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := tx.Exec("INSERT INTO schedule_assignments(schedule_id,scope,target) VALUES(?,?,?)",
			scheduleID, scope, target); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteSchedule(id string) error {
	_, err := s.db.Exec("DELETE FROM schedules WHERE id=?", id)
	return err
}

func (s *Store) GetSchedule(id string) (Schedule, error) {
	row := s.db.QueryRow(`SELECT id,name,mode,enabled,cron,timezone,window_minutes,jitter_seconds,
		max_concurrency,run_if_missed,notify,recipients,last_run_at,last_status,last_summary,created_at,updated_at
		FROM schedules WHERE id=?`, id)
	return scanSchedule(row)
}

func (s *Store) ListSchedules() ([]Schedule, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,enabled,cron,timezone,window_minutes,jitter_seconds,
		max_concurrency,run_if_missed,notify,recipients,last_run_at,last_status,last_summary,created_at,updated_at
		FROM schedules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var schedules []Schedule
	for rows.Next() {
		schedule, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		schedules = append(schedules, schedule)
	}
	return schedules, rows.Err()
}

type scheduleScanner interface {
	Scan(dest ...any) error
}

func scanSchedule(row scheduleScanner) (Schedule, error) {
	var schedule Schedule
	var enabled, missed int
	err := row.Scan(&schedule.ID, &schedule.Name, &schedule.Mode, &enabled, &schedule.Cron,
		&schedule.Timezone, &schedule.WindowMinutes, &schedule.JitterSeconds, &schedule.MaxConcurrency,
		&missed, &schedule.Notify, &schedule.Recipients, &schedule.LastRunAt, &schedule.LastStatus,
		&schedule.LastSummary, &schedule.CreatedAt, &schedule.UpdatedAt)
	schedule.Enabled = enabled == 1
	schedule.RunIfMissed = missed == 1
	return schedule, err
}

func (s *Store) ListScheduleAssignments(scheduleID string) ([]ScheduleAssignment, error) {
	rows, err := s.db.Query("SELECT schedule_id,scope,target FROM schedule_assignments WHERE schedule_id=? ORDER BY scope,target", scheduleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assignments []ScheduleAssignment
	for rows.Next() {
		var assignment ScheduleAssignment
		if err := rows.Scan(&assignment.ScheduleID, &assignment.Scope, &assignment.Target); err != nil {
			return nil, err
		}
		assignments = append(assignments, assignment)
	}
	return assignments, rows.Err()
}

func (s *Store) SetScheduleLastRunAt(id, at string) error {
	res, err := s.db.Exec("UPDATE schedules SET last_run_at=? WHERE id=?", at, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) SetScheduleResult(id, status, summary string) error {
	res, err := s.db.Exec("UPDATE schedules SET last_status=?, last_summary=? WHERE id=?", status, summary, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) StartRun(run Run) (Run, error) {
	if run.HostID == "" || run.Action == "" {
		return Run{}, errors.New("run host and action are required")
	}
	if run.ID == "" {
		run.ID = uuid.NewString()
	}
	if run.StartedAt == "" {
		run.StartedAt = crypto.Now()
	}
	if run.Status == "" {
		run.Status = "running"
	}
	_, err := s.db.Exec(`INSERT INTO runs(id,host_id,action,started_at,finished_at,status,exit_code,output,error,schedule_id)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, run.ID, run.HostID, run.Action, run.StartedAt, run.FinishedAt,
		run.Status, run.ExitCode, run.Output, run.Error, run.ScheduleID)
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

func (s *Store) FinishRun(id, status string, exitCode int, output, errorText, finishedAt string) error {
	if finishedAt == "" {
		finishedAt = crypto.Now()
	}
	res, err := s.db.Exec(`UPDATE runs SET finished_at=?,status=?,exit_code=?,output=?,error=? WHERE id=?`,
		finishedAt, status, exitCode, output, errorText, id)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) ListRuns(limit int, scheduleID, hostID string) ([]Run, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id,schedule_id,host_id,action,started_at,finished_at,status,exit_code,output,error
		FROM runs WHERE 1=1`
	var args []any
	if strings.TrimSpace(scheduleID) != "" {
		query += " AND schedule_id=?"
		args = append(args, scheduleID)
	}
	if strings.TrimSpace(hostID) != "" {
		query += " AND host_id=?"
		args = append(args, hostID)
	}
	query += " ORDER BY started_at DESC, id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []Run
	for rows.Next() {
		var run Run
		if err := rows.Scan(&run.ID, &run.ScheduleID, &run.HostID, &run.Action, &run.StartedAt,
			&run.FinishedAt, &run.Status, &run.ExitCode, &run.Output, &run.Error); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}
