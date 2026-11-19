package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

// Job is a durable manual operation. Jobs are created by the browser UI and
// executed by the controller even if the browser tab is reloaded or closed.
type Job struct {
	ID              string      `json:"id"`
	Kind            string      `json:"kind"`
	Status          string      `json:"status"`
	Actor           string      `json:"actor"`
	Title           string      `json:"title"`
	Detail          string      `json:"detail"`
	Payload         string      `json:"-"`
	Total           int         `json:"total"`
	Completed       int         `json:"completed"`
	Failed          int         `json:"failed"`
	Skipped         int         `json:"skipped"`
	CancelRequested bool        `json:"cancel_requested"`
	CreatedAt       string      `json:"created_at"`
	StartedAt       string      `json:"started_at"`
	FinishedAt      string      `json:"finished_at"`
	HeartbeatAt     string      `json:"heartbeat_at"`
	Targets         []JobTarget `json:"targets,omitempty"`
}

// JobTarget is one host attempt inside a job.
type JobTarget struct {
	JobID      string `json:"job_id"`
	HostID     string `json:"host_id"`
	HostName   string `json:"host_name"`
	Position   int    `json:"position"`
	Status     string `json:"status"`
	Stage      string `json:"stage"`
	Detail     string `json:"detail"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Error      string `json:"error"`
	Result     string `json:"result"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

const (
	JobQueued      = "queued"
	JobRunning     = "running"
	JobSucceeded   = "succeeded"
	JobFailed      = "failed"
	JobCancelled   = "cancelled"
	JobInterrupted = "interrupted"

	JobTargetPending     = "pending"
	JobTargetRunning     = "running"
	JobTargetSucceeded   = "succeeded"
	JobTargetFailed      = "failed"
	JobTargetSkipped     = "skipped"
	JobTargetCancelled   = "cancelled"
	JobTargetInterrupted = "interrupted"
)

// CreateJob stores a job and its ordered target list in one transaction.
func (s *Store) CreateJob(job Job, targets []JobTarget) (Job, error) {
	job.Kind = strings.TrimSpace(job.Kind)
	job.Title = strings.TrimSpace(job.Title)
	job.Actor = strings.TrimSpace(job.Actor)
	if job.Kind == "" || job.Title == "" || job.Actor == "" {
		return Job{}, errors.New("job kind, title, and actor are required")
	}
	if len(targets) == 0 {
		return Job{}, errors.New("job requires at least one host target")
	}
	if job.ID == "" {
		job.ID = uuid.NewString()
	}
	if job.Status == "" {
		job.Status = JobQueued
	}
	if job.Payload == "" {
		job.Payload = "{}"
	}
	now := crypto.Now()
	job.CreatedAt = now
	job.Total = len(targets)
	job.Completed = 0
	job.Failed = 0
	job.Skipped = 0

	tx, err := s.db.Begin()
	if err != nil {
		return Job{}, err
	}
	cancelRequested := 0
	if job.CancelRequested {
		cancelRequested = 1
	}
	_, err = tx.Exec(`INSERT INTO jobs(id,kind,status,actor,title,detail,payload,total,completed,failed,skipped,
		cancel_requested,created_at,started_at,finished_at,heartbeat_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.ID, job.Kind, job.Status, job.Actor, job.Title, job.Detail, job.Payload,
		job.Total, job.Completed, job.Failed, job.Skipped, cancelRequested,
		job.CreatedAt, job.StartedAt, job.FinishedAt, job.HeartbeatAt)
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	for index := range targets {
		target := &targets[index]
		target.JobID = job.ID
		target.Position = index
		if target.Status == "" {
			target.Status = JobTargetPending
		}
		_, err = tx.Exec(`INSERT INTO job_targets(job_id,host_id,host_name,position,status,stage,detail,
			exit_code,output,error,result,started_at,finished_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			job.ID, target.HostID, target.HostName, target.Position, target.Status, target.Stage,
			target.Detail, target.ExitCode, target.Output, target.Error, target.Result,
			target.StartedAt, target.FinishedAt)
		if err != nil {
			_ = tx.Rollback()
			return Job{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	job.Targets = targets
	return job, nil
}

// GetJob loads a job and its targets.
func (s *Store) GetJob(id string) (Job, error) {
	var job Job
	var cancelRequested int
	err := s.db.QueryRow(`SELECT id,kind,status,actor,title,detail,payload,total,completed,failed,skipped,
		cancel_requested,created_at,started_at,finished_at,heartbeat_at FROM jobs WHERE id=?`, id).
		Scan(&job.ID, &job.Kind, &job.Status, &job.Actor, &job.Title, &job.Detail, &job.Payload,
			&job.Total, &job.Completed, &job.Failed, &job.Skipped, &cancelRequested,
			&job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.HeartbeatAt)
	if err != nil {
		return Job{}, err
	}
	job.CancelRequested = cancelRequested == 1
	job.Targets, err = s.ListJobTargets(id)
	if err != nil {
		return Job{}, err
	}
	return job, nil
}

// ListJobTargets loads job targets in execution order.
func (s *Store) ListJobTargets(jobID string) ([]JobTarget, error) {
	rows, err := s.db.Query(`SELECT job_id,host_id,host_name,position,status,stage,detail,exit_code,
		output,error,result,started_at,finished_at FROM job_targets WHERE job_id=? ORDER BY position`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var targets []JobTarget
	for rows.Next() {
		var target JobTarget
		if err := rows.Scan(&target.JobID, &target.HostID, &target.HostName, &target.Position,
			&target.Status, &target.Stage, &target.Detail, &target.ExitCode, &target.Output,
			&target.Error, &target.Result, &target.StartedAt, &target.FinishedAt); err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return targets, rows.Err()
}

// ListJobSummaries returns the most recent jobs without their targets. It is
// used by the activity-dock poller to keep responses small on large fleets.
func (s *Store) ListJobSummaries(limit int) ([]Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 40
	}
	rows, err := s.db.Query(`SELECT id,kind,status,actor,title,detail,payload,total,completed,failed,skipped,
		cancel_requested,created_at,started_at,finished_at,heartbeat_at FROM jobs
		ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		var job Job
		var cancelRequested int
		if err := rows.Scan(&job.ID, &job.Kind, &job.Status, &job.Actor, &job.Title, &job.Detail,
			&job.Payload, &job.Total, &job.Completed, &job.Failed, &job.Skipped, &cancelRequested,
			&job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.HeartbeatAt); err != nil {
			return nil, err
		}
		job.CancelRequested = cancelRequested == 1
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ListJobs returns the most recent jobs, including their targets.
func (s *Store) ListJobs(limit int) ([]Job, error) {
	jobs, err := s.ListJobSummaries(limit)
	if err != nil {
		return nil, err
	}
	for index := range jobs {
		jobs[index].Targets, err = s.ListJobTargets(jobs[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return jobs, nil
}

// ListJobsByStatus returns jobs in one status, oldest first.
func (s *Store) ListJobsByStatus(status string) ([]Job, error) {
	rows, err := s.db.Query(`SELECT id FROM jobs WHERE status=? ORDER BY created_at`, status)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	jobs := make([]Job, 0, len(ids))
	for _, id := range ids {
		job, err := s.GetJob(id)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// ListJobPayloads returns every stored job payload keyed by job id. It is used
// only for staging-file cleanup; callers must not expose payloads.
func (s *Store) ListJobPayloads() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT id,payload FROM jobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	payloads := map[string]string{}
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		payloads[id] = payload
	}
	return payloads, rows.Err()
}

// ActiveJobHostIDs returns hosts already referenced by a queued or running job.
func (s *Store) ActiveJobHostIDs() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT host_id FROM job_targets
		WHERE job_id IN (SELECT id FROM jobs WHERE status IN ('queued','running'))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

// ClaimNextJob atomically moves the oldest queued job to running.
func (s *Store) ClaimNextJob() (Job, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Job{}, err
	}
	var id string
	err = tx.QueryRow(`SELECT id FROM jobs WHERE status=? ORDER BY created_at LIMIT 1`, JobQueued).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return Job{}, sql.ErrNoRows
	}
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	now := crypto.Now()
	result, err := tx.Exec(`UPDATE jobs SET status=?,started_at=CASE WHEN started_at='' THEN ? ELSE started_at END,
		heartbeat_at=? WHERE id=? AND status=?`, JobRunning, now, now, id, JobQueued)
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	if affected != 1 {
		_ = tx.Rollback()
		return Job{}, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	return s.GetJob(id)
}

// StartJobTarget marks a pending target as running.
func (s *Store) StartJobTarget(jobID, hostID, stage string) error {
	now := crypto.Now()
	result, err := s.db.Exec(`UPDATE job_targets SET status=?,stage=?,started_at=?,finished_at=''
		WHERE job_id=? AND host_id=?`, JobTargetRunning, stage, now, jobID, hostID)
	if err != nil {
		return err
	}
	return requireRow(result)
}

// SetJobTargetStage updates the visible stage for the running target.
func (s *Store) SetJobTargetStage(jobID, hostID, stage string) error {
	result, err := s.db.Exec(`UPDATE job_targets SET stage=? WHERE job_id=? AND host_id=?`, stage, jobID, hostID)
	if err != nil {
		return err
	}
	return requireRow(result)
}

// FinishJobTarget stores one target result and refreshes job counters.
func (s *Store) FinishJobTarget(target JobTarget) error {
	now := crypto.Now()
	if target.FinishedAt == "" {
		target.FinishedAt = now
	}
	result, err := s.db.Exec(`UPDATE job_targets SET status=?,stage=?,detail=?,exit_code=?,output=?,error=?,result=?,finished_at=?
		WHERE job_id=? AND host_id=?`,
		target.Status, target.Stage, target.Detail, target.ExitCode, target.Output, target.Error,
		target.Result, target.FinishedAt, target.JobID, target.HostID)
	if err != nil {
		return err
	}
	if err := requireRow(result); err != nil {
		return err
	}
	return s.refreshJobCounts(target.JobID)
}

func (s *Store) refreshJobCounts(jobID string) error {
	_, err := s.db.Exec(`UPDATE jobs SET
		completed=(SELECT COUNT(*) FROM job_targets WHERE job_id=? AND status IN ('succeeded','failed','skipped','cancelled','interrupted')),
		failed=(SELECT COUNT(*) FROM job_targets WHERE job_id=? AND status='failed'),
		skipped=(SELECT COUNT(*) FROM job_targets WHERE job_id=? AND status='skipped'),
		heartbeat_at=? WHERE id=?`, jobID, jobID, jobID, crypto.Now(), jobID)
	return err
}

// SetJobDetail updates the human-readable job detail.
func (s *Store) SetJobDetail(jobID, detail string) error {
	result, err := s.db.Exec(`UPDATE jobs SET detail=?,heartbeat_at=? WHERE id=?`, detail, crypto.Now(), jobID)
	if err != nil {
		return err
	}
	return requireRow(result)
}

// FinishJob marks a job terminal.
func (s *Store) FinishJob(jobID, status, detail string) error {
	now := crypto.Now()
	result, err := s.db.Exec(`UPDATE jobs SET status=?,detail=?,finished_at=?,heartbeat_at=? WHERE id=?`,
		status, detail, now, now, jobID)
	if err != nil {
		return err
	}
	return requireRow(result)
}

// RequestJobCancel asks the worker to stop after the current host.
func (s *Store) RequestJobCancel(jobID string) error {
	result, err := s.db.Exec(`UPDATE jobs SET cancel_requested=1 WHERE id=? AND status IN ('queued','running')`, jobID)
	if err != nil {
		return err
	}
	return requireRow(result)
}

// CancelQueuedJob immediately cancels a job that has not started.
func (s *Store) CancelQueuedJob(jobID, detail string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	now := crypto.Now()
	result, err := tx.Exec(`UPDATE jobs SET status=?,detail=?,cancel_requested=1,finished_at=?,heartbeat_at=?
		WHERE id=? AND status=?`, JobCancelled, detail, now, now, jobID, JobQueued)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if affected != 1 {
		_ = tx.Rollback()
		return errors.New("job is no longer queued")
	}
	if _, err := tx.Exec(`UPDATE job_targets SET status=?,detail=?,finished_at=?
		WHERE job_id=? AND status=?`, JobTargetCancelled, detail, now, jobID, JobTargetPending); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.refreshJobCounts(jobID)
}

// JobCancelRequested reports whether a cancel was requested.
func (s *Store) JobCancelRequested(jobID string) (bool, error) {
	var value int
	if err := s.db.QueryRow(`SELECT cancel_requested FROM jobs WHERE id=?`, jobID).Scan(&value); err != nil {
		return false, err
	}
	return value == 1, nil
}

// ResumeInterruptedJob returns a non-destructive running job to the queue.
func (s *Store) ResumeInterruptedJob(jobID, detail string) error {
	if _, err := s.db.Exec(`UPDATE job_targets SET status=?,stage='',detail=?,started_at='',finished_at=''
		WHERE job_id=? AND status=?`, JobTargetPending, detail, jobID, JobTargetRunning); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE jobs SET status=?,detail=?,finished_at='',heartbeat_at=? WHERE id=?`,
		JobQueued, detail, crypto.Now(), jobID); err != nil {
		return err
	}
	return s.refreshJobCounts(jobID)
}

// InterruptJob stops a destructive job after a controller restart.
func (s *Store) InterruptJob(jobID, detail string) error {
	if _, err := s.db.Exec(`UPDATE job_targets SET status=?,detail=?,finished_at=?
		WHERE job_id=? AND status=?`, JobTargetInterrupted, detail, crypto.Now(), jobID, JobTargetRunning); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE jobs SET status=?,detail=?,finished_at=?,heartbeat_at=? WHERE id=?`,
		JobInterrupted, detail, crypto.Now(), crypto.Now(), jobID); err != nil {
		return err
	}
	return s.refreshJobCounts(jobID)
}

// RetryJob requeues unfinished or failed targets for an explicit retry.
func (s *Store) RetryJob(jobID, detail string) error {
	if _, err := s.db.Exec(`UPDATE job_targets SET status=?,stage='',detail='',exit_code=0,output='',error='',result='',started_at='',finished_at=''
		WHERE job_id=? AND status IN ('pending','failed','skipped','cancelled','interrupted')`,
		JobTargetPending, jobID); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE jobs SET status=?,detail=?,cancel_requested=0,finished_at='',heartbeat_at=? WHERE id=?`,
		JobQueued, detail, crypto.Now(), jobID); err != nil {
		return err
	}
	return s.refreshJobCounts(jobID)
}

// DeleteJob removes a terminal job. Running jobs must be cancelled first.
func (s *Store) DeleteJob(jobID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	var status string
	if err := tx.QueryRow(`SELECT status FROM jobs WHERE id=?`, jobID).Scan(&status); err != nil {
		_ = tx.Rollback()
		return err
	}
	if status == JobQueued || status == JobRunning {
		_ = tx.Rollback()
		return fmt.Errorf("job is still %s", status)
	}
	if _, err := tx.Exec(`DELETE FROM job_targets WHERE job_id=?`, jobID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM jobs WHERE id=?`, jobID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
