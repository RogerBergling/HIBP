package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

const maxJobResultSize = 256 << 10

type jobTargetOutcome struct {
	Status   string
	Stage    string
	Detail   string
	ExitCode int
	Output   string
	Error    string
	Result   any
}

// RunJobs is the durable manual-operation worker. Destructive jobs interrupted
// by a restart are left for an explicit retry; non-destructive jobs resume from
// the next pending host. Only key-auth hosts with a trusted key and the
// restricted NOPASSWD helper are eligible.
func (s *Server) RunJobs(ctx context.Context) {
	s.recoverJobs()
	s.cleanupStagedPackages()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		job, err := s.store.ClaimNextJob()
		if errors.Is(err, sql.ErrNoRows) {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-s.jobWake:
			}
			continue
		}
		if err != nil {
			slog.Warn("jobs: claim next", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		s.runJob(ctx, job)
	}
}

func (s *Server) recoverJobs() {
	jobs, err := s.store.ListJobsByStatus(store.JobRunning)
	if err != nil {
		slog.Warn("jobs: list interrupted jobs", "error", err)
		return
	}
	for _, job := range jobs {
		if jobMeta(job.Kind).resumable {
			if err := s.store.ResumeInterruptedJob(job.ID, "Resumed after controller restart"); err != nil {
				slog.Warn("jobs: resume", "job", job.ID, "error", err)
				continue
			}
			_ = s.store.AddAudit("system", "job-resume", "job", job.ID, "resumed after controller restart")
			continue
		}
		if err := s.store.InterruptJob(job.ID, "Controller restarted during a destructive job; review the result and retry"); err != nil {
			slog.Warn("jobs: interrupt", "job", job.ID, "error", err)
			continue
		}
		_ = s.store.AddAudit("system", "job-interrupt", "job", job.ID, "interrupted after controller restart")
	}
}

func (s *Server) cleanupStagedPackages() {
	dir := s.jobPackageDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("jobs: read package staging directory", "error", err)
		}
		return
	}
	payloads, err := s.store.ListJobPayloads()
	if err != nil {
		slog.Warn("jobs: list package references", "error", err)
		return
	}
	referenced := map[string]bool{}
	for _, raw := range payloads {
		payload := parseJobPayload(raw)
		if payload.Package != nil && payload.Package.Path != "" {
			referenced[filepath.Clean(payload.Package.Path)] = true
		}
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if referenced[filepath.Clean(path)] {
			continue
		}
		if err := os.Remove(path); err != nil {
			slog.Warn("jobs: remove orphan staged package", "path", path, "error", err)
		}
	}
}

func (s *Server) runJob(ctx context.Context, job store.Job) {
	defer s.clearJobSudoPassword(job.ID)
	defer s.clearJobCheckmkPassword(job.ID)
	payload := parseJobPayload(job.Payload)
	targets, err := s.store.ListJobTargets(job.ID)
	if err != nil {
		_ = s.store.FinishJob(job.ID, store.JobFailed, "could not load job targets")
		_ = s.store.AddAudit("system", "job-failed", "job", job.ID, err.Error())
		return
	}
	_ = s.store.SetJobDetail(job.ID, "Starting…")
	cancelled := false
	for _, target := range targets {
		if target.Status != store.JobTargetPending {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if cancel, _ := s.store.JobCancelRequested(job.ID); cancel {
			cancelled = true
			s.cancelRemainingTargets(job, targets, target.Position)
			break
		}
		host, err := s.store.GetHost(target.HostID)
		if err != nil {
			s.finishTarget(job, target, jobTargetOutcome{
				Status: store.JobTargetSkipped, Stage: "skipped", Detail: "host no longer exists",
			})
			continue
		}
		if err := s.jobTargetEligible(job.Kind, host); err != nil {
			s.finishTarget(job, target, jobTargetOutcome{
				Status: store.JobTargetSkipped, Stage: "skipped", Detail: err.Error(),
			})
			continue
		}
		if !s.tryLockHost(host.ID) {
			s.finishTarget(job, target, jobTargetOutcome{
				Status: store.JobTargetSkipped, Stage: "skipped",
				Detail: "another operation is already running on this host",
			})
			continue
		}
		if err := s.store.StartJobTarget(job.ID, host.ID, "starting"); err != nil {
			s.unlockHost(host.ID)
			s.finishTarget(job, target, jobTargetOutcome{
				Status: store.JobTargetFailed, Stage: "failed", Detail: "could not start job target", Error: err.Error(),
			})
			continue
		}
		_ = s.store.SetJobDetail(job.ID, "Working on "+host.Name)
		outcome := s.executeJobTarget(ctx, job, payload, host)
		s.unlockHost(host.ID)
		if ctx.Err() != nil {
			outcome = jobTargetOutcome{
				Status: store.JobTargetInterrupted, Stage: "interrupted",
				Detail: "controller stopped during this target", Error: ctx.Err().Error(),
			}
			s.finishTarget(job, target, outcome)
			return
		}
		s.finishTarget(job, target, outcome)
	}
	final, err := s.store.GetJob(job.ID)
	if err != nil {
		slog.Warn("jobs: reload", "job", job.ID, "error", err)
		return
	}
	status := store.JobSucceeded
	if final.Failed > 0 {
		status = store.JobFailed
	}
	if cancelled {
		status = store.JobCancelled
	}
	succeeded := 0
	for _, target := range final.Targets {
		if target.Status == store.JobTargetSucceeded {
			succeeded++
		}
	}
	detail := fmt.Sprintf("Succeeded %d · failed %d · skipped %d", succeeded, final.Failed, final.Skipped)
	if final.Total == 0 {
		detail = "No hosts were processed"
	}
	if err := s.store.FinishJob(job.ID, status, detail); err != nil {
		slog.Warn("jobs: finish", "job", job.ID, "error", err)
		return
	}
	_ = s.store.AddAudit(job.Actor, "job-finish", "job", job.ID, status+" — "+detail)
	if status == store.JobSucceeded && final.Skipped == 0 {
		s.removeJobPackage(job)
	}
	s.wakeJobs()
}

func (s *Server) cancelRemainingTargets(job store.Job, targets []store.JobTarget, fromPosition int) {
	for _, target := range targets {
		if target.Position < fromPosition || target.Status != store.JobTargetPending {
			continue
		}
		s.finishTarget(job, target, jobTargetOutcome{
			Status: store.JobTargetCancelled, Stage: "cancelled", Detail: "cancelled by operator",
		})
	}
	_ = s.store.SetJobDetail(job.ID, "Stopping after the current host…")
}

func (s *Server) finishTarget(job store.Job, target store.JobTarget, outcome jobTargetOutcome) {
	resultText := ""
	if outcome.Result != nil {
		if raw, err := json.Marshal(outcome.Result); err == nil {
			resultText = truncateJobResult(string(raw))
		}
	}
	target.Status = outcome.Status
	target.Stage = outcome.Stage
	target.Detail = truncateRunOutput(outcome.Detail)
	target.ExitCode = outcome.ExitCode
	target.Output = truncateRunOutput(outcome.Output)
	target.Error = truncateRunOutput(outcome.Error)
	target.Result = resultText
	if err := s.store.FinishJobTarget(target); err != nil {
		slog.Warn("jobs: finish target", "job", job.ID, "host", target.HostName, "error", err)
	}
}

func truncateJobResult(value string) string {
	if len(value) <= maxJobResultSize {
		return value
	}
	return value[:maxJobResultSize]
}

func redactJobSecret(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[redacted]")
}

func (s *Server) jobTargetEligible(kind string, host store.Host) error {
	if err := s.jobHostRunnable(host); err != nil {
		return err
	}
	if (kind == "reboot" || kind == "cleanup-preview" || kind == "cleanup-apply") && s.isControllerHost(host) {
		return errors.New("the HIBP controller is excluded from bulk cleanup and reboot; use the per-host action")
	}
	return nil
}

func (s *Server) jobHostRunnable(host store.Host) error {
	if host.AuthType != "key" {
		return errors.New("password-auth hosts require interactive per-host actions")
	}
	key, err := s.store.GetHostKey(host.ID)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("host key is not trusted; test and trust it first")
	}
	return nil
}

func (s *Server) executeJobTarget(ctx context.Context, job store.Job, payload jobPayload, host store.Host) jobTargetOutcome {
	switch job.Kind {
	case "helper-setup":
		return s.runHelperSetupJob(ctx, job, host)
	case "facts":
		return s.runFactsJob(ctx, job, host)
	case "patch-preview":
		return s.runPatchPreviewJob(ctx, job, host)
	case "patch-apply":
		return s.runPatchApplyJob(ctx, job, payload, host)
	case "cleanup-preview":
		return s.runCleanupJob(ctx, job, host, false)
	case "cleanup-apply":
		return s.runCleanupJob(ctx, job, host, true)
	case "reboot":
		return s.runRebootJob(ctx, job, host)
	case "package-install":
		return s.runPackageInstallJob(ctx, job, payload, host)
	case "runbook":
		return s.runRunbookJob(ctx, job, payload, host)
	default:
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "unknown job kind", Error: "unknown job kind"}
	}
}

func (s *Server) stage(job store.Job, host store.Host, stage string) {
	_ = s.store.SetJobTargetStage(job.ID, host.ID, stage)
}

func (s *Server) runHelperSetupJob(ctx context.Context, job store.Job, host store.Host) jobTargetOutcome {
	s.stage(job, host, "installing helper")
	key, err := s.store.GetHostKey(host.ID)
	if err != nil || key == nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "host key is not trusted", Error: "host key is not trusted"}
	}
	sudoPassword := s.jobSudoPassword(job.ID)
	if s.demo != nil {
		output, err := s.demo.InstallHelper(ctx, host, nil, sudoPassword)
		if err != nil {
			return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
		}
		var facts helper.Facts
		if json.Unmarshal([]byte(output), &facts) == nil {
			_ = s.store.SaveFactsAs(job.Actor, host.ID, storeFactsFromHelper(facts))
		}
		_ = s.store.AddAudit(job.Actor, "bootstrap-helper", "host", host.ID, "demo: installed restricted helper")
		return jobTargetOutcome{
			Status: store.JobTargetSucceeded, Stage: "done", Detail: "demo helper installed and verified",
			Output: output, Result: map[string]any{"output": output},
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "locate controller binary", Error: err.Error()}
	}
	info, err := os.Stat(executable)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "stat controller binary", Error: err.Error()}
	}
	if info.Size() > maxHelperBinarySize {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "controller binary is too large", Error: "controller binary exceeds the 100 MiB helper limit"}
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "read controller binary", Error: err.Error()}
	}
	output, err := remote.InstallHelper(ctx, s.hostTarget(host, ""), remoteHostKey(key), binary, sudoPassword)
	if errors.Is(err, remote.ErrSudoPasswordRequired) {
		return jobTargetOutcome{
			Status: store.JobTargetSkipped, Stage: "skipped",
			Detail: "sudo -n is not available; create a new job with a shared sudo password or use the per-host Setup action",
			Error:  err.Error(),
		}
	}
	if errors.Is(err, remote.ErrSudoPasswordInvalid) {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "shared sudo password rejected on this host", Error: err.Error()}
	}
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "sudo is not available") || strings.Contains(lower, "passwordless") {
			return jobTargetOutcome{
				Status: store.JobTargetSkipped, Stage: "skipped",
				Detail: "helper installation needs non-interactive sudo; provide a shared sudo password or use the per-host Setup action",
				Error:  err.Error(),
			}
		}
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	var facts helper.Facts
	if json.Unmarshal([]byte(output), &facts) == nil {
		_ = s.store.SaveFactsAs(job.Actor, host.ID, storeFactsFromHelper(facts))
	}
	_ = s.store.AddAudit(job.Actor, "bootstrap-helper", "host", host.ID, "installed restricted helper from job")
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done", Detail: "helper installed and verified",
		Output: output, Result: map[string]any{"output": output},
	}
}

func (s *Server) runRunbookJob(ctx context.Context, job store.Job, payload jobPayload, host store.Host) jobTargetOutcome {
	if payload.Runbook == nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "runbook action is missing", Error: "runbook action is missing"}
	}
	spec := *payload.Runbook
	displayAction := spec.Action
	if spec.Action == "checkmk-register" {
		displayAction = "cmk-agent-ctl register"
	}
	s.stage(job, host, displayAction)
	request := helper.RunbookRequest{Unit: spec.Unit, Packages: spec.Packages}
	timeout := 15 * time.Minute
	if spec.Action == "checkmk-register" {
		if spec.Checkmk == nil {
			return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "Checkmk settings are missing", Error: "checkmk settings are missing"}
		}
		password := s.jobCheckmkPassword(job.ID)
		if password == "" {
			return jobTargetOutcome{
				Status: store.JobTargetFailed, Stage: "failed",
				Detail: "Checkmk password is no longer available; queue a new registration",
				Error:  "the transient Checkmk password was not retained across the job lifetime",
			}
		}
		request.Checkmk = &helper.CheckmkRegisterRequest{
			Hostname: spec.Checkmk.Hostname,
			Server:   spec.Checkmk.Server,
			Site:     spec.Checkmk.Site,
			User:     spec.Checkmk.User,
			Password: password,
		}
		timeout = 5 * time.Minute
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "encode runbook", Error: err.Error()}
	}
	output, code, err := s.runHelperActionInput(ctx, host, spec.Action, "", s.jobSudoPassword(job.ID), string(requestJSON), timeout)
	if errors.Is(err, errSudoPasswordRequired) {
		return jobTargetOutcome{Status: store.JobTargetSkipped, Stage: "skipped", Detail: "sudo -n is not available; provide a shared sudo password or use an interactive runbook", Error: err.Error()}
	}
	if errors.Is(err, errSudoPasswordInvalid) {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "sudo password rejected", Error: err.Error()}
	}
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	if request.Checkmk != nil {
		// Defense in depth: the helper already redacts the password, but never
		// let a helper regression write it into the durable job result.
		output = redactJobSecret(output, request.Checkmk.Password)
	}
	var result helper.Result
	if json.Unmarshal([]byte(output), &result) != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "invalid runbook result", Error: output}
	}
	displayOutput := runbookOutput(result)
	if !result.OK {
		detail := result.Action + " failed"
		if result.Error != "" {
			detail = result.Error
		}
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", ExitCode: code, Detail: shortRunSummary(detail), Output: displayOutput, Error: result.Error}
	}
	_ = s.store.AddAudit(job.Actor, "runbook", "host", host.ID, displayAction)
	return jobTargetOutcome{Status: store.JobTargetSucceeded, Stage: "done", ExitCode: code, Detail: displayAction + " completed", Output: displayOutput, Result: result}
}

// runbookOutput shows the fixed command before its captured output so the job
// view makes clear what ran. The helper redacts secrets in Command.
func runbookOutput(result helper.Result) string {
	if result.Command == "" {
		return result.Output
	}
	if result.Output == "" {
		return "command: " + result.Command
	}
	return "command: " + result.Command + "\n\n" + result.Output
}

func (s *Server) runFactsJob(ctx context.Context, job store.Job, host store.Host) jobTargetOutcome {
	s.stage(job, host, "collecting facts")
	facts, err := s.collectFactsForHost(ctx, job.Actor, host, "", "")
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done",
		Detail: fmt.Sprintf("%d pending update(s)", facts.PendingUpdates),
		Result: facts,
	}
}

func (s *Server) runPatchPreviewJob(ctx context.Context, job store.Job, host store.Host) jobTargetOutcome {
	s.stage(job, host, "resolving package changes")
	preview, hash, err := s.runPatchPreview(ctx, host, "", "")
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	if !preview.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: "patch preview failed",
			ExitCode: preview.ExitCode, Output: preview.Output, Error: preview.Error,
			Result: map[string]any{"preview": preview, "preview_hash": hash},
		}
	}
	_ = s.store.AddAudit(job.Actor, "patch-preview", "host", host.ID,
		fmt.Sprintf("upgrade=%d install=%d remove=%d exit=%d",
			preview.Counts["upgrade"], preview.Counts["install"], preview.Counts["remove"], preview.ExitCode))
	total := preview.Counts["upgrade"] + preview.Counts["install"] + preview.Counts["remove"] +
		preview.Counts["downgrade"] + preview.Counts["reinstall"]
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done",
		Detail: fmt.Sprintf("%d package change(s)", total), Output: preview.Output,
		Result: map[string]any{"preview": preview, "preview_hash": hash},
	}
}

func (s *Server) runPatchApplyJob(ctx context.Context, job store.Job, payload jobPayload, host store.Host) jobTargetOutcome {
	spec, ok := payload.Previews[host.ID]
	if !ok || strings.TrimSpace(spec.PreviewHash) == "" {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "no reviewed preview", Error: "no reviewed preview for this host"}
	}
	s.stage(job, host, "re-checking preview")
	preview, hash, err := s.runPatchPreview(ctx, host, "", "")
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	if !preview.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: "patch preview failed",
			ExitCode: preview.ExitCode, Output: preview.Output, Error: preview.Error,
			Result: map[string]any{"preview": preview, "preview_hash": hash},
		}
	}
	if hash != spec.PreviewHash {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: "package list changed — re-run the preview",
			Error: "the package preview changed before apply", Result: map[string]any{"preview": preview, "preview_hash": hash},
		}
	}
	if preview.Counts["remove"] > 0 && !spec.AllowRemovals {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: "package removals were not confirmed",
			Error: "the preview includes package removals", Result: map[string]any{"preview": preview, "preview_hash": hash},
		}
	}
	if len(preview.Packages) == 0 {
		_ = s.store.AddAudit(job.Actor, "patch-apply-noop", "host", host.ID, "no package changes")
		return jobTargetOutcome{Status: store.JobTargetSucceeded, Stage: "done", Detail: "no package changes"}
	}
	s.stage(job, host, "applying updates")
	output, code, err := s.runHelper(ctx, host, "apply", "", "", 45*time.Minute)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	result := parseHelperResult("apply", output, code)
	_ = s.store.AddAudit(job.Actor, "patch-apply", "host", host.ID, fmt.Sprintf("exit=%d", code))
	if !result.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: "package apply failed",
			ExitCode: result.ExitCode, Output: result.Output, Error: result.Error,
		}
	}
	s.stage(job, host, "refreshing facts")
	var facts *helper.Facts
	if refreshed, factsErr := s.collectFactsForHost(ctx, job.Actor, host, "", ""); factsErr == nil {
		facts = &refreshed
	}
	response := patchResponse{Result: result, Preview: &preview, PreviewHash: hash, Facts: facts}
	detail := "patched"
	status := store.JobTargetSucceeded
	errorText := ""
	if payload.RebootAfterPatch {
		s.stage(job, host, "checking reboot state")
		required, requested, rebootOutput, rebootErr := s.checkAndReboot(ctx, host, "", "")
		response.RebootRequired = required
		response.RebootRequested = requested
		response.RebootOutput = rebootOutput
		if rebootErr != nil {
			response.RebootError = rebootErr.Error()
			status = store.JobTargetFailed
			errorText = "patch applied but reboot failed: " + rebootErr.Error()
			detail += " · reboot check failed"
			_ = s.store.AddAudit(job.Actor, "reboot-after-patch-failed", "host", host.ID, shortRunSummary(rebootErr.Error()))
		} else if requested {
			detail += " · reboot requested"
			_ = s.store.AddAudit(job.Actor, "reboot", "host", host.ID, "requested after patch")
		} else if required {
			detail += " · reboot still required"
		}
	}
	if facts != nil {
		detail += " · facts refreshed"
	}
	stage := "done"
	if status == store.JobTargetFailed {
		stage = "failed"
	}
	return jobTargetOutcome{
		Status: status, Stage: stage, Detail: detail,
		ExitCode: result.ExitCode, Output: result.Output, Error: errorText, Result: response,
	}
}

func (s *Server) runCleanupJob(ctx context.Context, job store.Job, host store.Host, apply bool) jobTargetOutcome {
	action := "cleanup-check"
	timeout := 10 * time.Minute
	stage := "scanning orphaned packages"
	if apply {
		action = "cleanup-apply"
		timeout = 30 * time.Minute
		stage = "removing orphaned packages"
	}
	s.stage(job, host, stage)
	output, code, err := s.runHelper(ctx, host, action, "", "", timeout)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	var result helper.CleanupResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "helper returned invalid cleanup JSON", Error: err.Error(), Output: output}
	}
	if code != 0 && result.OK {
		result.OK = false
		if result.Error == "" {
			result.Error = fmt.Sprintf("helper exited with code %d", code)
		}
	}
	if apply && result.OK {
		_ = s.store.UpdateOrphanedPackages(host.ID, result.Remaining)
	}
	detail := fmt.Sprintf("orphaned=%d", result.Count)
	if apply {
		detail = fmt.Sprintf("removed=%d remaining=%d", result.Count, result.Remaining)
	}
	_ = s.store.AddAudit(job.Actor, action, "host", host.ID, detail)
	if !result.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(result.Error),
			ExitCode: code, Output: result.Output, Error: result.Error, Result: result,
		}
	}
	if !result.Supported {
		return jobTargetOutcome{
			Status: store.JobTargetSkipped, Stage: "skipped", Detail: "cleanup is not supported for this package manager",
			Output: result.Output, Result: result,
		}
	}
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done", Detail: detail,
		ExitCode: code, Output: result.Output, Result: result,
	}
}

func (s *Server) runRebootJob(ctx context.Context, job store.Job, host store.Host) jobTargetOutcome {
	s.stage(job, host, "requesting reboot")
	output, code, err := s.runHelper(ctx, host, "reboot", "", "", 2*time.Minute)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	result := helper.Result{Action: "reboot", OK: code == 0, ExitCode: code, Output: output}
	if code == 0 {
		_ = s.store.SetHostStatus(host.ID, "unknown")
	} else {
		result.Error = fmt.Sprintf("reboot exited with code %d", code)
	}
	_ = s.store.AddAudit(job.Actor, "reboot", "host", host.ID, fmt.Sprintf("exit=%d", code))
	if !result.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: result.Error,
			ExitCode: code, Output: output, Error: result.Error, Result: result,
		}
	}
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done", Detail: "reboot requested; the host may disconnect",
		Output: output, Result: result,
	}
}

func (s *Server) runPackageInstallJob(ctx context.Context, job store.Job, payload jobPayload, host store.Host) jobTargetOutcome {
	if payload.Package == nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: "package details are missing", Error: "package details are missing"}
	}
	if err := packageManagerCompatible(host, payload.Package.Name); err != nil {
		return jobTargetOutcome{Status: store.JobTargetSkipped, Stage: "skipped", Detail: err.Error()}
	}
	s.stage(job, host, "uploading package")
	result, err := s.runPackageInstall(ctx, host, payload.Package)
	if err != nil {
		return jobTargetOutcome{Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(err.Error()), Error: err.Error()}
	}
	if !result.OK {
		return jobTargetOutcome{
			Status: store.JobTargetFailed, Stage: "failed", Detail: shortRunSummary(result.Error),
			ExitCode: result.ExitCode, Output: result.Output, Error: result.Error, Result: result,
		}
	}
	s.stage(job, host, "refreshing facts")
	var facts *helper.Facts
	if refreshed, factsErr := s.collectFactsForHost(ctx, job.Actor, host, "", ""); factsErr == nil {
		facts = &refreshed
	}
	_ = s.store.AddAudit(job.Actor, "install-package", "host", host.ID,
		fmt.Sprintf("package=%s sha256=%s exit=%d", payload.Package.Name, payload.Package.SHA256, result.ExitCode))
	return jobTargetOutcome{
		Status: store.JobTargetSucceeded, Stage: "done",
		Detail:   "installed " + payload.Package.Name,
		ExitCode: result.ExitCode, Output: result.Output,
		Result: map[string]any{"install": result, "facts": facts},
	}
}
