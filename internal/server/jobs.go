package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/RogerBergling/hibp/internal/helper"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/google/uuid"
)

const maxJobHosts = 500

var runbookPackagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}$`)
var (
	runbookCheckmkHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	runbookCheckmkSitePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	runbookCheckmkUserPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$`)
)

type jobKindMeta struct {
	label     string
	resumable bool
}

var jobKinds = map[string]jobKindMeta{
	"helper-setup":    {label: "Helper setup", resumable: true},
	"facts":           {label: "Facts collection", resumable: true},
	"patch-preview":   {label: "Patch preview", resumable: true},
	"patch-apply":     {label: "Patch apply", resumable: false},
	"cleanup-preview": {label: "Cleanup preview", resumable: true},
	"cleanup-apply":   {label: "Cleanup apply", resumable: false},
	"reboot":          {label: "Reboot", resumable: false},
	"package-install": {label: "Package install", resumable: false},
	"runbook":         {label: "Runbook", resumable: false},
}

type jobPreviewSpec struct {
	PreviewHash   string `json:"preview_hash"`
	AllowRemovals bool   `json:"allow_removals"`
}

type jobPackageSpec struct {
	Name   string            `json:"name"`
	Path   string            `json:"path"`
	SHA256 string            `json:"sha256"`
	Size   int64             `json:"size"`
	Env    map[string]string `json:"env,omitempty"`
}

type jobCheckmkSpec struct {
	Hostname string `json:"hostname,omitempty"`
	Server   string `json:"server"`
	Site     string `json:"site"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
}

type jobRunbookSpec struct {
	Action   string          `json:"action"`
	Unit     string          `json:"unit,omitempty"`
	Packages []string        `json:"packages,omitempty"`
	Checkmk  *jobCheckmkSpec `json:"checkmk,omitempty"`
}

type jobPayload struct {
	Confirm          string                    `json:"confirm,omitempty"`
	RebootAfterPatch bool                      `json:"reboot_after_patch,omitempty"`
	Previews         map[string]jobPreviewSpec `json:"previews,omitempty"`
	Package          *jobPackageSpec           `json:"package,omitempty"`
	Runbook          *jobRunbookSpec           `json:"runbook,omitempty"`
}

type jobCreateRequest struct {
	Kind             string                    `json:"kind"`
	HostIDs          []string                  `json:"host_ids"`
	Confirm          string                    `json:"confirm"`
	RebootAfterPatch bool                      `json:"reboot_after_patch"`
	Previews         map[string]jobPreviewSpec `json:"previews"`
	SudoPassword     string                    `json:"sudo_password"`
	Runbook          *jobRunbookSpec           `json:"runbook"`
}

type jobPackageView struct {
	Name    string   `json:"name"`
	SHA256  string   `json:"sha256"`
	Size    int64    `json:"size"`
	EnvKeys []string `json:"env_keys,omitempty"`
}

type jobTargetView struct {
	HostID       string          `json:"host_id"`
	HostName     string          `json:"host_name"`
	Status       string          `json:"status"`
	Stage        string          `json:"stage"`
	Detail       string          `json:"detail"`
	ExitCode     int             `json:"exit_code"`
	Output       string          `json:"output,omitempty"`
	Error        string          `json:"error,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	HasOutput    bool            `json:"has_output,omitempty"`
	PreviewTotal int             `json:"preview_total,omitempty"`
	CleanupCount int             `json:"cleanup_count,omitempty"`
	StartedAt    string          `json:"started_at"`
	FinishedAt   string          `json:"finished_at"`
}

type jobView struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind"`
	Label           string          `json:"label"`
	Status          string          `json:"status"`
	Actor           string          `json:"actor"`
	Title           string          `json:"title"`
	Detail          string          `json:"detail"`
	Total           int             `json:"total"`
	Completed       int             `json:"completed"`
	Failed          int             `json:"failed"`
	Skipped         int             `json:"skipped"`
	CancelRequested bool            `json:"cancel_requested"`
	CreatedAt       string          `json:"created_at"`
	StartedAt       string          `json:"started_at"`
	FinishedAt      string          `json:"finished_at"`
	Package         *jobPackageView `json:"package,omitempty"`
	Targets         []jobTargetView `json:"targets"`
}

func jobMeta(kind string) jobKindMeta {
	if meta, ok := jobKinds[kind]; ok {
		return meta
	}
	return jobKindMeta{label: kind}
}

func jobLabel(kind string) string {
	return jobMeta(kind).label
}

func parseJobPayload(raw string) jobPayload {
	var payload jobPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return jobPayload{}
	}
	return payload
}

func jobViewFromStore(job store.Job, full bool) jobView {
	view := jobView{
		ID: job.ID, Kind: job.Kind, Label: jobLabel(job.Kind), Status: job.Status,
		Actor: job.Actor, Title: job.Title, Detail: job.Detail, Total: job.Total,
		Completed: job.Completed, Failed: job.Failed, Skipped: job.Skipped,
		CancelRequested: job.CancelRequested, CreatedAt: job.CreatedAt,
		StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		Targets: make([]jobTargetView, 0, len(job.Targets)),
	}
	payload := parseJobPayload(job.Payload)
	if payload.Package != nil {
		view.Package = &jobPackageView{
			Name: payload.Package.Name, SHA256: payload.Package.SHA256,
			Size: payload.Package.Size, EnvKeys: sortedKeys(payload.Package.Env),
		}
	}
	for _, target := range job.Targets {
		previewTotal, cleanupCount := targetResultSummary(target.Result)
		targetView := jobTargetView{
			HostID: target.HostID, HostName: target.HostName, Status: target.Status,
			Stage: target.Stage, Detail: target.Detail, ExitCode: target.ExitCode,
			HasOutput:    target.Output != "" || target.Error != "",
			PreviewTotal: previewTotal, CleanupCount: cleanupCount,
			StartedAt: target.StartedAt, FinishedAt: target.FinishedAt,
		}
		if full {
			targetView.Output = target.Output
			targetView.Error = target.Error
			if json.Valid([]byte(target.Result)) && target.Result != "" {
				targetView.Result = json.RawMessage(target.Result)
			}
		}
		view.Targets = append(view.Targets, targetView)
	}
	return view
}

func targetResultSummary(raw string) (previewTotal, cleanupCount int) {
	if raw == "" {
		return 0, 0
	}
	var value struct {
		Preview *helper.PreviewResult `json:"preview"`
		OK      bool                  `json:"ok"`
		Count   int                   `json:"count"`
	}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return 0, 0
	}
	if value.Preview != nil && value.Preview.OK {
		for _, count := range value.Preview.Counts {
			previewTotal += count
		}
	}
	if value.OK {
		cleanupCount = value.Count
	}
	return previewTotal, cleanupCount
}

func sortedKeys(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) setJobSudoPassword(jobID, password string) {
	if jobID == "" || password == "" {
		return
	}
	s.jobSudoMu.Lock()
	if s.jobSudoPasswords == nil {
		s.jobSudoPasswords = make(map[string]string)
	}
	s.jobSudoPasswords[jobID] = password
	s.jobSudoMu.Unlock()
}

func (s *Server) jobSudoPassword(jobID string) string {
	s.jobSudoMu.Lock()
	defer s.jobSudoMu.Unlock()
	return s.jobSudoPasswords[jobID]
}

func (s *Server) clearJobSudoPassword(jobID string) {
	s.jobSudoMu.Lock()
	delete(s.jobSudoPasswords, jobID)
	s.jobSudoMu.Unlock()
}

func (s *Server) setJobCheckmkPassword(jobID, password string) {
	if jobID == "" || password == "" {
		return
	}
	s.jobCheckmkMu.Lock()
	if s.jobCheckmkPasswords == nil {
		s.jobCheckmkPasswords = make(map[string]string)
	}
	s.jobCheckmkPasswords[jobID] = password
	s.jobCheckmkMu.Unlock()
}

func (s *Server) jobCheckmkPassword(jobID string) string {
	s.jobCheckmkMu.Lock()
	defer s.jobCheckmkMu.Unlock()
	return s.jobCheckmkPasswords[jobID]
}

func (s *Server) clearJobCheckmkPassword(jobID string) {
	s.jobCheckmkMu.Lock()
	delete(s.jobCheckmkPasswords, jobID)
	s.jobCheckmkMu.Unlock()
}

func validateCheckmkRunbook(spec *jobCheckmkSpec) error {
	if spec == nil {
		return errors.New("checkmk settings are required")
	}
	spec.Hostname = strings.TrimSpace(spec.Hostname)
	spec.Server = strings.TrimSpace(spec.Server)
	spec.Site = strings.TrimSpace(spec.Site)
	spec.User = strings.TrimSpace(spec.User)
	if spec.Hostname != "" && spec.Hostname != "%HOSTNAME" {
		if !runbookCheckmkHostPattern.MatchString(strings.TrimSuffix(spec.Hostname, ".")) {
			return errors.New("a valid Checkmk hostname is required")
		}
	}
	host, port, hasPort := strings.Cut(spec.Server, ":")
	if !runbookCheckmkHostPattern.MatchString(host) || strings.Contains(port, ":") {
		return errors.New("a valid Checkmk server is required")
	}
	if hasPort {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return errors.New("a valid Checkmk server port is required")
		}
	}
	if !runbookCheckmkSitePattern.MatchString(spec.Site) {
		return errors.New("a valid Checkmk site is required")
	}
	if !runbookCheckmkUserPattern.MatchString(spec.User) {
		return errors.New("a valid Checkmk user is required")
	}
	if spec.Password == "" || len(spec.Password) > 256 {
		return errors.New("the Checkmk password is required (maximum 256 characters)")
	}
	for _, char := range spec.Password {
		if char < 0x20 || char == 0x7f {
			return errors.New("the Checkmk password contains unsupported control characters")
		}
	}
	return nil
}

func (s *Server) validateJobRequest(request jobCreateRequest) (string, []string, jobPayload, error) {
	kind := strings.TrimSpace(request.Kind)
	if _, ok := jobKinds[kind]; !ok {
		return "", nil, jobPayload{}, errors.New("unknown job kind")
	}
	if request.SudoPassword != "" && kind != "helper-setup" && kind != "runbook" {
		return "", nil, jobPayload{}, errors.New("sudo_password is only accepted for helper setup and runbook jobs")
	}
	if len(request.HostIDs) == 0 {
		return "", nil, jobPayload{}, errors.New("select at least one host")
	}
	if len(request.HostIDs) > maxJobHosts {
		return "", nil, jobPayload{}, fmt.Errorf("at most %d hosts are allowed per job", maxJobHosts)
	}
	seen := map[string]bool{}
	hostIDs := make([]string, 0, len(request.HostIDs))
	for _, raw := range request.HostIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			return "", nil, jobPayload{}, errors.New("host id is required")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		hostIDs = append(hostIDs, id)
	}
	for _, id := range hostIDs {
		if _, err := s.store.GetHost(id); err != nil {
			return "", nil, jobPayload{}, errors.New("one or more selected hosts no longer exist")
		}
	}
	active, err := s.store.ActiveJobHostIDs()
	if err != nil {
		return "", nil, jobPayload{}, err
	}
	var conflicts []string
	for _, id := range hostIDs {
		if active[id] {
			host, _ := s.store.GetHost(id)
			conflicts = append(conflicts, host.Name)
		}
	}
	if len(conflicts) > 0 {
		return "", nil, jobPayload{}, fmt.Errorf("an active job already includes: %s", strings.Join(conflicts, ", "))
	}

	payload := jobPayload{
		Confirm:          strings.ToLower(strings.TrimSpace(request.Confirm)),
		RebootAfterPatch: request.RebootAfterPatch,
		Previews:         request.Previews,
		Runbook:          request.Runbook,
	}
	switch kind {
	case "helper-setup":
		if payload.Confirm != "setup" {
			return "", nil, jobPayload{}, errors.New("confirm must be \"setup\" for a helper setup job")
		}
	case "patch-apply":
		if payload.Confirm != "apply" {
			return "", nil, jobPayload{}, errors.New("confirm must be \"apply\" for a patch apply job")
		}
		if len(payload.Previews) == 0 {
			return "", nil, jobPayload{}, errors.New("a patch apply job requires a reviewed preview for each host")
		}
		for _, id := range hostIDs {
			spec, ok := payload.Previews[id]
			if !ok || strings.TrimSpace(spec.PreviewHash) == "" {
				return "", nil, jobPayload{}, errors.New("every selected host needs a reviewed patch preview")
			}
		}
	case "cleanup-apply":
		if payload.Confirm != "cleanup" {
			return "", nil, jobPayload{}, errors.New("confirm must be \"cleanup\" for a cleanup apply job")
		}
	case "reboot":
		if payload.Confirm != "reboot" {
			return "", nil, jobPayload{}, errors.New("confirm must be \"reboot\" for a reboot job")
		}
	case "package-install":
		if payload.Confirm != "install" {
			return "", nil, jobPayload{}, errors.New("confirm must be \"install\" for a package install job")
		}
	case "runbook":
		if payload.Runbook == nil {
			return "", nil, jobPayload{}, errors.New("runbook action is required")
		}
		action := strings.TrimSpace(payload.Runbook.Action)
		payload.Runbook.Action = action
		switch action {
		case "service-restart", "service-enable", "service-disable":
			if payload.Confirm != "run" {
				return "", nil, jobPayload{}, errors.New("confirm must be \"run\" for a service runbook")
			}
			if !monitorServicePattern.MatchString(strings.TrimSpace(payload.Runbook.Unit)) {
				return "", nil, jobPayload{}, errors.New("a valid systemd unit is required")
			}
			payload.Runbook.Packages = nil
		case "package-remove-preview", "package-install-preview":
			if payload.Confirm != "preview" {
				return "", nil, jobPayload{}, errors.New("confirm must be \"preview\" for a package preview")
			}
			if len(payload.Runbook.Packages) == 0 {
				return "", nil, jobPayload{}, errors.New("at least one package is required")
			}
		case "package-remove-apply":
			if payload.Confirm != "remove" {
				return "", nil, jobPayload{}, errors.New("confirm must be \"remove\" for a package removal")
			}
			if len(payload.Runbook.Packages) == 0 {
				return "", nil, jobPayload{}, errors.New("at least one package is required")
			}
		case "package-install-apply":
			if payload.Confirm != "install" {
				return "", nil, jobPayload{}, errors.New("confirm must be \"install\" for a package installation")
			}
			if len(payload.Runbook.Packages) == 0 {
				return "", nil, jobPayload{}, errors.New("at least one package is required")
			}
		case "checkmk-register":
			if payload.Confirm != "register" {
				return "", nil, jobPayload{}, errors.New("confirm must be \"register\" for Checkmk registration")
			}
			if err := validateCheckmkRunbook(payload.Runbook.Checkmk); err != nil {
				return "", nil, jobPayload{}, err
			}
			payload.Runbook.Unit = ""
			payload.Runbook.Packages = nil
		default:
			return "", nil, jobPayload{}, errors.New("unsupported runbook action")
		}
		if payload.Runbook.Action != "checkmk-register" {
			payload.Runbook.Checkmk = nil
		}
		cleaned := make([]string, 0, len(payload.Runbook.Packages))
		for _, pkg := range payload.Runbook.Packages {
			pkg = strings.TrimSpace(pkg)
			if pkg == "" {
				continue
			}
			if !runbookPackagePattern.MatchString(pkg) {
				return "", nil, jobPayload{}, fmt.Errorf("invalid package name %q", pkg)
			}
			cleaned = append(cleaned, pkg)
		}
		payload.Runbook.Packages = cleaned
	}
	return kind, hostIDs, payload, nil
}

func (s *Server) createJob(actor string, request jobCreateRequest, pkg *jobPackageSpec) (store.Job, error) {
	kind, hostIDs, payload, err := s.validateJobRequest(request)
	if err != nil {
		return store.Job{}, err
	}
	if kind == "package-install" {
		if pkg == nil || strings.TrimSpace(pkg.Path) == "" {
			return store.Job{}, errors.New("package data is required")
		}
		if err := helper.ValidateInstallEnvironment(pkg.Env); err != nil {
			return store.Job{}, err
		}
	}
	payload.Package = pkg
	checkmkPassword := ""
	if payload.Runbook != nil && payload.Runbook.Checkmk != nil {
		// Keep the registration password in controller memory only. The job
		// payload is persisted and must never contain it.
		checkmkPassword = payload.Runbook.Checkmk.Password
		payload.Runbook.Checkmk.Password = ""
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return store.Job{}, err
	}
	targets := make([]store.JobTarget, 0, len(hostIDs))
	for _, id := range hostIDs {
		host, err := s.store.GetHost(id)
		if err != nil {
			return store.Job{}, err
		}
		targets = append(targets, store.JobTarget{
			HostID: host.ID, HostName: host.Name, Status: store.JobTargetPending,
		})
	}
	title := jobTitle(kind, targets, pkg)
	jobID := uuid.NewString()
	if (kind == "helper-setup" || kind == "runbook") && request.SudoPassword != "" {
		s.setJobSudoPassword(jobID, request.SudoPassword)
	}
	if checkmkPassword != "" {
		s.setJobCheckmkPassword(jobID, checkmkPassword)
	}
	job, err := s.store.CreateJob(store.Job{
		ID: jobID, Kind: kind, Status: store.JobQueued, Actor: actor, Title: title,
		Detail: "Queued", Payload: string(rawPayload),
	}, targets)
	if err != nil {
		s.clearJobSudoPassword(jobID)
		s.clearJobCheckmkPassword(jobID)
		return store.Job{}, err
	}
	_ = s.store.AddAudit(actor, "job-create", "job", job.ID, title)
	s.wakeJobs()
	return job, nil
}

func jobTitle(kind string, targets []store.JobTarget, pkg *jobPackageSpec) string {
	count := len(targets)
	suffix := "host"
	if count != 1 {
		suffix = "hosts"
	}
	switch kind {
	case "helper-setup":
		return fmt.Sprintf("Set up helpers on %d %s", count, suffix)
	case "facts":
		return fmt.Sprintf("Collect facts from %d %s", count, suffix)
	case "patch-preview":
		return fmt.Sprintf("Patch preview for %d %s", count, suffix)
	case "patch-apply":
		return fmt.Sprintf("Apply updates on %d %s", count, suffix)
	case "cleanup-preview":
		return fmt.Sprintf("Cleanup preview for %d %s", count, suffix)
	case "cleanup-apply":
		return fmt.Sprintf("Clean up unused packages on %d %s", count, suffix)
	case "reboot":
		return fmt.Sprintf("Reboot %d %s", count, suffix)
	case "package-install":
		name := "package"
		if pkg != nil && strings.TrimSpace(pkg.Name) != "" {
			name = pkg.Name
		}
		return fmt.Sprintf("Install %s on %d %s", name, count, suffix)
	case "runbook":
		return fmt.Sprintf("Runbook for %d %s", count, suffix)
	default:
		return fmt.Sprintf("Job for %d %s", count, suffix)
	}
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit := 40
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	jobs, err := s.store.ListJobSummaries(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]jobView, 0, len(jobs))
	for _, job := range jobs {
		views = append(views, jobViewFromStore(job, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": views})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	full := r.URL.Query().Get("full") == "1"
	writeJSON(w, http.StatusOK, map[string]any{"job": jobViewFromStore(job, full)})
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var request jobCreateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	job, err := s.createJob(s.auditActor(r), request, nil)
	if err != nil {
		if strings.Contains(err.Error(), "already includes") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"job": jobViewFromStore(job, false)})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != store.JobQueued && job.Status != store.JobRunning {
		writeError(w, http.StatusBadRequest, "job is not active")
		return
	}
	if job.Status == store.JobQueued {
		if err := s.store.CancelQueuedJob(job.ID, "cancelled before start"); err != nil {
			if strings.Contains(err.Error(), "no longer queued") {
				writeError(w, http.StatusConflict, "job has already started; cancel after the current host")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = s.store.AddAudit(s.auditActor(r), "job-cancel", "job", job.ID, "cancelled before start")
		s.clearJobSudoPassword(job.ID)
		s.clearJobCheckmkPassword(job.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if err := s.store.RequestJobCancel(job.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "job-cancel", "job", job.ID, "stop after current host")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRetryJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	retryable := job.Status == store.JobInterrupted || job.Status == store.JobFailed ||
		job.Status == store.JobCancelled || (job.Status == store.JobSucceeded && job.Skipped > 0)
	if !retryable {
		writeError(w, http.StatusBadRequest, "only an interrupted, failed, cancelled, or partly skipped job can be retried")
		return
	}
	if err := s.store.RetryJob(job.ID, "Retry requested"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "job-retry", "job", job.ID, "requeued")
	s.wakeJobs()
	updated, _ := s.store.GetJob(job.ID)
	writeJSON(w, http.StatusOK, map[string]any{"job": jobViewFromStore(updated, false)})
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status == store.JobQueued || job.Status == store.JobRunning {
		writeError(w, http.StatusConflict, "cancel the job before deleting it")
		return
	}
	s.removeJobPackage(job)
	if err := s.store.DeleteJob(job.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(s.auditActor(r), "job-delete", "job", job.ID, job.Title)
	s.clearJobSudoPassword(job.ID)
	s.clearJobCheckmkPassword(job.ID)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// wakeJobs notifies the worker without blocking when it is already awake.
func (s *Server) wakeJobs() {
	select {
	case s.jobWake <- struct{}{}:
	default:
	}
}
