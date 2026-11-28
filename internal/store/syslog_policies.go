package store

import (
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

// SyslogPolicy is a safe log-routing rule. It can reclassify or suppress an
// event; suppressed events are retained. Critical events and protected kernel
// failures are guarded in the server policy engine.
type SyslogPolicy struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	Scope           string `json:"scope"` // fleet or host
	HostID          string `json:"host_id,omitempty"`
	MatchType       string `json:"match_type"` // contains or regex
	Pattern         string `json:"pattern"`
	Category        string `json:"category,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Suppress        bool   `json:"suppress"`
	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	CreatedBy       string `json:"created_by"`
	SuppressedCount int    `json:"suppressed_count,omitempty"`
	GuardrailCount  int    `json:"guardrail_count,omitempty"`
}

type SyslogPolicyUsage struct {
	Suppressed int
	Guardrails int
}

// SyslogPolicyUsage reports how many retained events each policy suppressed or
// attempted to suppress but was blocked by a guardrail.
func (s *Store) SyslogPolicyUsage() (map[string]SyslogPolicyUsage, error) {
	rows, err := s.db.Query(`SELECT policy_id,
		SUM(CASE WHEN suppressed=1 THEN 1 ELSE 0 END),
		SUM(CASE WHEN guardrail=1 THEN 1 ELSE 0 END)
		FROM host_events WHERE policy_id <> '' GROUP BY policy_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	usage := make(map[string]SyslogPolicyUsage)
	for rows.Next() {
		var policyID string
		var item SyslogPolicyUsage
		if err := rows.Scan(&policyID, &item.Suppressed, &item.Guardrails); err != nil {
			return nil, err
		}
		usage[policyID] = item
	}
	return usage, rows.Err()
}

func (s *Store) CreateSyslogPolicy(policy SyslogPolicy) (SyslogPolicy, error) {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Pattern = strings.TrimSpace(policy.Pattern)
	if policy.Name == "" || policy.Pattern == "" {
		return SyslogPolicy{}, errors.New("policy name and pattern are required")
	}
	policy.ID = uuid.NewString()
	now := crypto.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	suppress := 0
	if policy.Suppress {
		suppress = 1
	}
	enabled := 0
	if policy.Enabled {
		enabled = 1
	}
	var hostID any
	if policy.HostID != "" {
		hostID = policy.HostID
	}
	if _, err := s.db.Exec(`INSERT INTO syslog_policies
		(id,name,description,scope,host_id,match_type,pattern,category,severity,suppress,priority,enabled,created_at,updated_at,created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		policy.ID, policy.Name, policy.Description, policy.Scope, hostID,
		policy.MatchType, policy.Pattern, policy.Category, policy.Severity, suppress,
		policy.Priority, enabled, policy.CreatedAt, policy.UpdatedAt, policy.CreatedBy); err != nil {
		return SyslogPolicy{}, err
	}
	return policy, nil
}

func (s *Store) UpdateSyslogPolicy(policy SyslogPolicy) error {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Pattern = strings.TrimSpace(policy.Pattern)
	if policy.ID == "" || policy.Name == "" || policy.Pattern == "" {
		return errors.New("policy id, name, and pattern are required")
	}
	policy.UpdatedAt = crypto.Now()
	suppress := 0
	if policy.Suppress {
		suppress = 1
	}
	enabled := 0
	if policy.Enabled {
		enabled = 1
	}
	var hostID any
	if policy.HostID != "" {
		hostID = policy.HostID
	}
	result, err := s.db.Exec(`UPDATE syslog_policies SET
		name=?,description=?,scope=?,host_id=?,match_type=?,pattern=?,category=?,severity=?,
		suppress=?,priority=?,enabled=?,updated_at=? WHERE id=?`,
		policy.Name, policy.Description, policy.Scope, hostID, policy.MatchType,
		policy.Pattern, policy.Category, policy.Severity, suppress, policy.Priority,
		enabled, policy.UpdatedAt, policy.ID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("syslog policy not found")
	}
	return nil
}

func (s *Store) DeleteSyslogPolicy(id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("policy id is required")
	}
	result, err := s.db.Exec("DELETE FROM syslog_policies WHERE id=?", id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("syslog policy not found")
	}
	return nil
}

func (s *Store) GetSyslogPolicy(id string) (SyslogPolicy, error) {
	var policy SyslogPolicy
	var suppress, enabled int
	err := s.db.QueryRow(`SELECT id,name,description,scope,COALESCE(host_id,''),match_type,pattern,category,severity,
		suppress,priority,enabled,created_at,updated_at,created_by
		FROM syslog_policies WHERE id=?`, id).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Scope, &policy.HostID,
		&policy.MatchType, &policy.Pattern, &policy.Category, &policy.Severity,
		&suppress, &policy.Priority, &enabled, &policy.CreatedAt, &policy.UpdatedAt, &policy.CreatedBy)
	policy.Suppress = suppress == 1
	policy.Enabled = enabled == 1
	return policy, err
}

func (s *Store) ListSyslogPolicies() ([]SyslogPolicy, error) {
	rows, err := s.db.Query(`SELECT id,name,description,scope,COALESCE(host_id,''),match_type,pattern,category,severity,
		suppress,priority,enabled,created_at,updated_at,created_by
		FROM syslog_policies
		ORDER BY priority ASC, CASE scope WHEN 'host' THEN 0 ELSE 1 END, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]SyslogPolicy, 0)
	for rows.Next() {
		var policy SyslogPolicy
		var suppress, enabled int
		if err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Scope,
			&policy.HostID, &policy.MatchType, &policy.Pattern, &policy.Category,
			&policy.Severity, &suppress, &policy.Priority, &enabled, &policy.CreatedAt,
			&policy.UpdatedAt, &policy.CreatedBy); err != nil {
			return nil, err
		}
		policy.Suppress = suppress == 1
		policy.Enabled = enabled == 1
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}
