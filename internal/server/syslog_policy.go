package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/store"
)

const (
	syslogPolicyCacheTTL = 10 * time.Second
	maxSyslogPolicies    = 200
	maxPolicyPatternLen  = 512
)

var syslogPolicyCategoryPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Protected kernel failures are always critical and can never be suppressed or
// downgraded by a policy. This list intentionally favors safety over silence.
var protectedKernelPatterns = []string{
	"out of memory", "oom-kill", "oom killer", "killed process",
	"i/o error", "input/output error", "buffer i/o error", "metadata i/o error",
	"ext4-fs error", "ext4-fs warning", "journal abort", "filesystem error",
	"xfs (", "xfs error", "btrfs error", "btrfs warning",
	"remounting filesystem read-only", "remount-ro", "read-only file system",
	"lost page write", "filesystem corrupted", "device offline",
	"md:", "md/raid", "raid degraded", "raid failed", "raid array degraded",
	"device-mapper", "thin-pool",
	"nvme timeout", "nvme reset", "nvme error", "ata bus error", "ata error",
	"ata link", "medium error", "critical medium error", "blk_update_request",
	"machine check", "mce:", "hardware error", "edac",
	"pcie bus error", "aer:", "iommu error", "dmar error",
	"kernel panic", "kernel bug", "kernel oops", "oops:", "general protection fault",
	"unable to handle kernel", "rip:", "call trace", "blocked for more than",
	"hung task", "task hung", "soft lockup", "hard lockup",
	"rcu_sched detected stalls", "cpu stuck", "watchdog:", "netdev watchdog",
	"tx timeout", "reset adapter", "firmware error",
	"critical temperature", "over temperature", "thermal shutdown",
	"thermal throttling", "power failure", "segfault", "bad page",
}

type syslogPolicyRuntime struct {
	policy store.SyslogPolicy
	regex  *regexp.Regexp
}

type syslogPolicyDecision struct {
	Category   string
	Severity   string
	PolicyID   string
	PolicyName string
	Suppressed bool
	Guardrail  bool
}

type syslogPolicyRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
	HostID      string `json:"host_id"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Suppress    bool   `json:"suppress"`
	Priority    int    `json:"priority"`
	Enabled     *bool  `json:"enabled"`
}

type syslogPolicyPreviewRequest struct {
	syslogPolicyRequest
	Window string `json:"window"`
	Limit  int    `json:"limit"`
}

func (s *Server) loadSyslogPolicyRuntime() []syslogPolicyRuntime {
	s.syslogPolicyMu.Lock()
	defer s.syslogPolicyMu.Unlock()
	if !s.syslogPolicyCacheAt.IsZero() && time.Since(s.syslogPolicyCacheAt) < syslogPolicyCacheTTL {
		return s.syslogPolicyCache
	}
	policies, err := s.store.ListSyslogPolicies()
	if err != nil {
		slog.Warn("syslog policy: load", "error", err)
		s.syslogPolicyCacheAt = time.Now()
		return s.syslogPolicyCache
	}
	runtime := make([]syslogPolicyRuntime, 0, len(policies))
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		compiled, err := compileSyslogPolicy(policy)
		if err != nil {
			slog.Warn("syslog policy: compile", "policy", policy.Name, "error", err)
			continue
		}
		runtime = append(runtime, compiled)
	}
	s.syslogPolicyCache = runtime
	s.syslogPolicyCacheAt = time.Now()
	return runtime
}

func (s *Server) invalidateSyslogPolicyCache() {
	s.syslogPolicyMu.Lock()
	s.syslogPolicyCacheAt = time.Time{}
	s.syslogPolicyMu.Unlock()
}

func compileSyslogPolicy(policy store.SyslogPolicy) (syslogPolicyRuntime, error) {
	runtime := syslogPolicyRuntime{policy: policy}
	if policy.MatchType == "regex" {
		compiled, err := regexp.Compile("(?i)" + policy.Pattern)
		if err != nil {
			return runtime, err
		}
		runtime.regex = compiled
	}
	return runtime, nil
}

func (runtime syslogPolicyRuntime) matches(hostID, lowerMessage string) bool {
	switch runtime.policy.Scope {
	case "host":
		if runtime.policy.HostID != hostID {
			return false
		}
	case "fleet":
	default:
		return false
	}
	if runtime.policy.MatchType == "regex" {
		return runtime.regex != nil && runtime.regex.MatchString(lowerMessage)
	}
	return strings.Contains(lowerMessage, strings.ToLower(runtime.policy.Pattern))
}

func (s *Server) evaluateSyslogPolicy(hostID, message, baseCategory, baseSeverity string) syslogPolicyDecision {
	decision := syslogPolicyDecision{
		Category: baseCategory,
		Severity: baseSeverity,
	}
	lower := strings.ToLower(message)
	for _, runtime := range s.loadSyslogPolicyRuntime() {
		if !runtime.matches(hostID, lower) {
			continue
		}
		decision.PolicyID = runtime.policy.ID
		decision.PolicyName = runtime.policy.Name
		if runtime.policy.Category != "" {
			decision.Category = runtime.policy.Category
		}
		if runtime.policy.Severity != "" {
			decision.Severity = runtime.policy.Severity
		}
		decision.Suppressed = runtime.policy.Suppress
		break
	}
	applySyslogGuardrails(&decision, baseCategory, baseSeverity, message)
	return decision
}

// applySyslogGuardrails is a hard safety boundary. Authentication failures,
// security threats, any event whose base severity is critical, and protected
// kernel failures cannot be suppressed or downgraded.
func applySyslogGuardrails(decision *syslogPolicyDecision, baseCategory, baseSeverity, message string) {
	policyChanged := decision.Category != baseCategory || decision.Severity != baseSeverity || decision.Suppressed
	baseProtected := baseCategory == "auth_failure" || baseCategory == "security_threat"
	finalProtected := decision.Category == "auth_failure" || decision.Category == "security_threat"
	if baseProtected {
		decision.Category = baseCategory
		decision.Severity = "critical"
		decision.Suppressed = false
		decision.Guardrail = true
	} else if finalProtected {
		decision.Severity = "critical"
		decision.Suppressed = false
		decision.Guardrail = true
	}
	if baseSeverity == "critical" {
		decision.Category = baseCategory
		decision.Severity = "critical"
		decision.Suppressed = false
		if policyChanged {
			decision.Guardrail = true
		}
	}
	lower := strings.ToLower(message)
	if strings.Contains(lower, "kernel:") || strings.Contains(lower, "kernel[") {
		for _, pattern := range protectedKernelPatterns {
			if strings.Contains(lower, pattern) {
				decision.Severity = "critical"
				decision.Suppressed = false
				decision.Guardrail = true
				break
			}
		}
	}
	if decision.Severity == "critical" && decision.Suppressed {
		decision.Suppressed = false
		decision.Guardrail = true
	}
}

func (s *Server) validateSyslogPolicy(request syslogPolicyRequest, existing *store.SyslogPolicy, actor string, checkLimit bool) (store.SyslogPolicy, error) {
	policy := store.SyslogPolicy{
		Name:        strings.TrimSpace(request.Name),
		Description: strings.TrimSpace(request.Description),
		Scope:       strings.ToLower(strings.TrimSpace(request.Scope)),
		HostID:      strings.TrimSpace(request.HostID),
		MatchType:   strings.ToLower(strings.TrimSpace(request.MatchType)),
		Pattern:     strings.TrimSpace(request.Pattern),
		Category:    strings.ToLower(strings.TrimSpace(request.Category)),
		Severity:    strings.ToLower(strings.TrimSpace(request.Severity)),
		Suppress:    request.Suppress,
		Priority:    request.Priority,
		Enabled:     true,
		CreatedBy:   actor,
	}
	if request.Enabled != nil {
		policy.Enabled = *request.Enabled
	} else if existing != nil {
		policy.Enabled = existing.Enabled
	}
	if existing != nil {
		policy.ID = existing.ID
		policy.CreatedAt = existing.CreatedAt
		policy.CreatedBy = existing.CreatedBy
	}
	if policy.Name == "" || len(policy.Name) > 128 {
		return store.SyslogPolicy{}, errors.New("policy name is required and must be at most 128 characters")
	}
	if len(policy.Description) > 512 {
		return store.SyslogPolicy{}, errors.New("policy description must be at most 512 characters")
	}
	if policy.Scope == "" {
		policy.Scope = "fleet"
	}
	switch policy.Scope {
	case "fleet":
		policy.HostID = ""
	case "host":
		if policy.HostID == "" {
			return store.SyslogPolicy{}, errors.New("host scope requires a host")
		}
		if _, err := s.store.GetHost(policy.HostID); err != nil {
			return store.SyslogPolicy{}, errors.New("host scope references an unknown host")
		}
	default:
		return store.SyslogPolicy{}, errors.New("policy scope must be fleet or host")
	}
	if policy.MatchType == "" {
		policy.MatchType = "contains"
	}
	if policy.MatchType != "contains" && policy.MatchType != "regex" {
		return store.SyslogPolicy{}, errors.New("match_type must be contains or regex")
	}
	if policy.Pattern == "" || len(policy.Pattern) > maxPolicyPatternLen {
		return store.SyslogPolicy{}, errors.New("pattern is required and must be at most 512 characters")
	}
	if policy.MatchType == "regex" {
		compiled, err := regexp.Compile("(?i)" + policy.Pattern)
		if err != nil {
			return store.SyslogPolicy{}, fmt.Errorf("invalid regex: %w", err)
		}
		matchedAll := true
		for _, sample := range []string{"alpha", "12345", "x y z", "some log message", "kernel: test"} {
			if !compiled.MatchString(sample) {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			return store.SyslogPolicy{}, errors.New("refusing a policy that matches every syslog event")
		}
	}
	if policy.Category != "" && !syslogPolicyCategoryPattern.MatchString(policy.Category) {
		return store.SyslogPolicy{}, errors.New("category must contain only lowercase letters, digits, and underscores")
	}
	switch policy.Severity {
	case "", "info", "warning", "critical":
	default:
		return store.SyslogPolicy{}, errors.New("severity must be info, warning, critical, or empty")
	}
	if policy.Category == "" && policy.Severity == "" && !policy.Suppress {
		return store.SyslogPolicy{}, errors.New("policy must change category, change severity, or suppress the event")
	}
	if policy.Suppress {
		if len(policy.Pattern) < 3 {
			return store.SyslogPolicy{}, errors.New("suppression patterns must be at least 3 characters")
		}
		if policy.Severity == "critical" {
			return store.SyslogPolicy{}, errors.New("cannot suppress an event classified as critical")
		}
		if policy.Category == "auth_failure" || policy.Category == "security_threat" {
			return store.SyslogPolicy{}, errors.New("cannot suppress authentication or security-threat events")
		}
	}
	if policy.Pattern != "" {
		normalizedPattern := strings.ReplaceAll(strings.ToLower(policy.Pattern), " ", "")
		broadKernel := false
		switch normalizedPattern {
		case ".*", "^.*$", "^.*", ".*$", "(?s).*", "(?i).*", "^.+$":
			if policy.Suppress || policy.Severity == "info" || policy.Severity == "warning" {
				return store.SyslogPolicy{}, errors.New("refusing to suppress or downgrade every syslog event")
			}
		case "kernel", "kernel:", "kernel[", "kernel.*", ".*kernel.*", "^kernel", "kernel$",
			"(?i)kernel", "(?i)kernel:", "(?i)kernel.*", "(?i).*kernel.*":
			broadKernel = true
		}
		if policy.MatchType == "regex" {
			if compiled, err := regexp.Compile("(?i)" + policy.Pattern); err == nil {
				matched := 0
				for _, sample := range []string{"kernel: test", "kernel[123]: test", "prefix kernel: test"} {
					if compiled.MatchString(sample) {
						matched++
					}
				}
				if matched == 3 {
					broadKernel = true
				}
			}
		}
		if broadKernel && (policy.Suppress || policy.Severity == "info" || policy.Severity == "warning") {
			return store.SyslogPolicy{}, errors.New("refusing to suppress or downgrade all kernel events; use a specific driver or message pattern")
		}
	}
	if policy.Priority == 0 {
		policy.Priority = 100
	}
	if policy.Priority < 1 || policy.Priority > 1000 {
		return store.SyslogPolicy{}, errors.New("priority must be between 1 and 1000")
	}
	if checkLimit && existing == nil {
		policies, err := s.store.ListSyslogPolicies()
		if err != nil {
			return store.SyslogPolicy{}, err
		}
		if len(policies) >= maxSyslogPolicies {
			return store.SyslogPolicy{}, fmt.Errorf("at most %d syslog policies are supported", maxSyslogPolicies)
		}
	}
	return policy, nil
}

func (s *Server) handleListSyslogPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListSyslogPolicies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if policies == nil {
		policies = []store.SyslogPolicy{}
	}
	if usage, err := s.store.SyslogPolicyUsage(); err == nil {
		for index := range policies {
			if item, ok := usage[policies[index].ID]; ok {
				policies[index].SuppressedCount = item.Suppressed
				policies[index].GuardrailCount = item.Guardrails
			}
		}
	}
	guardrails := make([]string, len(protectedKernelPatterns))
	copy(guardrails, protectedKernelPatterns)
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies, "guardrails": guardrails,
	})
}

func syslogPolicyAuditDetail(policy store.SyslogPolicy) string {
	return fmt.Sprintf("name=%q scope=%s pattern=%q category=%q severity=%q suppress=%t priority=%d enabled=%t",
		policy.Name, policy.Scope, policy.Pattern, policy.Category, policy.Severity,
		policy.Suppress, policy.Priority, policy.Enabled)
}

func (s *Server) handleCreateSyslogPolicy(w http.ResponseWriter, r *http.Request) {
	var request syslogPolicyRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	policy, err := s.validateSyslogPolicy(request, nil, s.auditActor(r), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	policy, err = s.store.CreateSyslogPolicy(policy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.invalidateSyslogPolicyCache()
	_ = s.store.AddAudit(s.auditActor(r), "syslog-policy-create", "syslog_policy", policy.ID, syslogPolicyAuditDetail(policy))
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) handleUpdateSyslogPolicy(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetSyslogPolicy(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "syslog policy not found")
		return
	}
	var request syslogPolicyRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	policy, err := s.validateSyslogPolicy(request, &existing, s.auditActor(r), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateSyslogPolicy(policy); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.invalidateSyslogPolicyCache()
	_ = s.store.AddAudit(s.auditActor(r), "syslog-policy-update", "syslog_policy", policy.ID, syslogPolicyAuditDetail(policy))
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) handleDeleteSyslogPolicy(w http.ResponseWriter, r *http.Request) {
	existing, err := s.store.GetSyslogPolicy(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "syslog policy not found")
		return
	}
	if err := s.store.DeleteSyslogPolicy(existing.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.invalidateSyslogPolicyCache()
	_ = s.store.AddAudit(s.auditActor(r), "syslog-policy-delete", "syslog_policy", existing.ID, existing.Name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handlePreviewSyslogPolicy(w http.ResponseWriter, r *http.Request) {
	var request syslogPolicyPreviewRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	policy, err := s.validateSyslogPolicy(request.syslogPolicyRequest, nil, s.auditActor(r), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runtime, err := compileSyslogPolicy(policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	window := strings.TrimSpace(request.Window)
	if window == "" {
		window = "24h"
	}
	_, since := parseEventWindow(window)
	limit := request.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	events, err := s.store.ListHostEventsFilteredIncludingSuppressed(limit, since, "", true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	matched := 0
	wouldSuppress := 0
	protectedMatches := 0
	samples := make([]map[string]any, 0, 20)
	for _, event := range events {
		lower := strings.ToLower(event.Message)
		if !runtime.matches(event.HostID, lower) {
			continue
		}
		matched++
		decision := syslogPolicyDecision{
			Category: event.Category,
			Severity: event.Severity,
		}
		if runtime.policy.Category != "" {
			decision.Category = runtime.policy.Category
		}
		if runtime.policy.Severity != "" {
			decision.Severity = runtime.policy.Severity
		}
		decision.Suppressed = runtime.policy.Suppress
		applySyslogGuardrails(&decision, event.Category, event.Severity, event.Message)
		if decision.Suppressed {
			wouldSuppress++
		}
		if decision.Guardrail {
			protectedMatches++
		}
		if len(samples) < 20 {
			samples = append(samples, map[string]any{
				"host_id":   event.HostID,
				"message":   event.Message,
				"before":    map[string]any{"category": event.Category, "severity": event.Severity, "suppressed": event.Suppressed},
				"after":     map[string]any{"category": decision.Category, "severity": decision.Severity, "suppressed": decision.Suppressed},
				"guardrail": decision.Guardrail,
				"policy":    runtime.policy.Name,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scanned": len(events), "matched": matched, "would_suppress": wouldSuppress,
		"protected_matches": protectedMatches, "samples": samples,
	})
}
