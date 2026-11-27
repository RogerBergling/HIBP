package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

type Monitor struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Type            string              `json:"type"`
	Target          string              `json:"target"`
	Warning         float64             `json:"warning"`
	Critical        float64             `json:"critical"`
	IntervalSeconds int                 `json:"interval_seconds"`
	RepeatMinutes   int                 `json:"repeat_minutes"`
	CooldownMinutes int                 `json:"cooldown_minutes"`
	Recipients      string              `json:"recipients"`
	Enabled         bool                `json:"enabled"`
	LastCheckedAt   string              `json:"last_checked_at"`
	CreatedAt       string              `json:"created_at"`
	UpdatedAt       string              `json:"updated_at"`
	Assignments     []MonitorAssignment `json:"assignments,omitempty"`
	States          []MonitorState      `json:"states,omitempty"`
}

type MonitorAssignment struct {
	MonitorID string `json:"monitor_id"`
	Scope     string `json:"scope"`
	Target    string `json:"target"`
}

type MonitorState struct {
	MonitorID    string `json:"monitor_id"`
	HostID       string `json:"host_id"`
	Status       string `json:"status"`
	Message      string `json:"message"`
	CheckedAt    string `json:"checked_at"`
	ChangedAt    string `json:"changed_at"`
	LastNotified string `json:"last_notified"`
}

type AlertEvent struct {
	ID        int64  `json:"id"`
	MonitorID string `json:"monitor_id"`
	HostID    string `json:"host_id"`
	Status    string `json:"status"`
	Subject   string `json:"subject"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"created_at"`
	Emailed   bool   `json:"emailed"`
	Error     string `json:"error"`
}

type ServiceState struct {
	HostID   string `json:"host_id"`
	Unit     string `json:"unit"`
	State    string `json:"state"`
	LastSeen string `json:"last_seen"`
}

// ServiceBaseline is the per-host set of systemd units observed running at the
// first successful service collection. It is used to detect service drift
// without creating one monitor per unit.
type ServiceBaseline struct {
	HostID    string `json:"host_id"`
	Unit      string `json:"unit"`
	State     string `json:"state"`
	Expected  bool   `json:"expected"`
	Excluded  bool   `json:"excluded"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

func (s *Store) CreateMonitor(monitor Monitor) (Monitor, error) {
	monitor.Name = strings.TrimSpace(monitor.Name)
	if monitor.Name == "" || monitor.Type == "" {
		return Monitor{}, errors.New("monitor name and type are required")
	}
	monitor.ID = uuid.NewString()
	now := crypto.Now()
	monitor.CreatedAt = now
	monitor.UpdatedAt = now
	tx, err := s.db.Begin()
	if err != nil {
		return Monitor{}, err
	}
	enabled := 0
	if monitor.Enabled {
		enabled = 1
	}
	if _, err := tx.Exec(`INSERT INTO monitors(id,name,type,target,warning,critical,interval_seconds,
		repeat_minutes,cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, monitor.ID, monitor.Name, monitor.Type, monitor.Target,
		monitor.Warning, monitor.Critical, monitor.IntervalSeconds, monitor.RepeatMinutes,
		monitor.CooldownMinutes, monitor.Recipients, enabled, "", now, now); err != nil {
		_ = tx.Rollback()
		return Monitor{}, err
	}
	if err := insertAssignments(tx, monitor.ID, monitor.Assignments); err != nil {
		_ = tx.Rollback()
		return Monitor{}, err
	}
	return monitor, tx.Commit()
}

func (s *Store) UpdateMonitor(monitor Monitor) error {
	monitor.Name = strings.TrimSpace(monitor.Name)
	if monitor.ID == "" || monitor.Name == "" || monitor.Type == "" {
		return errors.New("monitor id, name, and type are required")
	}
	now := crypto.Now()
	monitor.UpdatedAt = now
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	enabled := 0
	if monitor.Enabled {
		enabled = 1
	}
	res, err := tx.Exec(`UPDATE monitors SET name=?,type=?,target=?,warning=?,critical=?,interval_seconds=?,
		repeat_minutes=?,cooldown_minutes=?,recipients=?,enabled=?,updated_at=? WHERE id=?`,
		monitor.Name, monitor.Type, monitor.Target, monitor.Warning, monitor.Critical,
		monitor.IntervalSeconds, monitor.RepeatMinutes, monitor.CooldownMinutes, monitor.Recipients,
		enabled, now, monitor.ID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		_ = tx.Rollback()
		return sql.ErrNoRows
	}
	if _, err := tx.Exec("DELETE FROM monitor_assignments WHERE monitor_id=?", monitor.ID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := insertAssignments(tx, monitor.ID, monitor.Assignments); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func insertAssignments(tx *sql.Tx, monitorID string, assignments []MonitorAssignment) error {
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
			return errors.New("non-fleet monitor assignment requires a target")
		}
		key := scope + "\x00" + target
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := tx.Exec("INSERT INTO monitor_assignments(monitor_id,scope,target) VALUES(?,?,?)",
			monitorID, scope, target); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteMonitor(id string) error {
	_, err := s.db.Exec("DELETE FROM monitors WHERE id=?", id)
	return err
}

func (s *Store) GetMonitor(id string) (Monitor, error) {
	row := s.db.QueryRow(`SELECT id,name,type,target,warning,critical,interval_seconds,repeat_minutes,
		cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at FROM monitors WHERE id=?`, id)
	return scanMonitor(row)
}

func (s *Store) ListMonitors() ([]Monitor, error) {
	rows, err := s.db.Query(`SELECT id,name,type,target,warning,critical,interval_seconds,repeat_minutes,
		cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at FROM monitors ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var monitors []Monitor
	for rows.Next() {
		monitor, err := scanMonitor(rows)
		if err != nil {
			return nil, err
		}
		monitors = append(monitors, monitor)
	}
	return monitors, rows.Err()
}

type monitorScanner interface {
	Scan(dest ...any) error
}

func scanMonitor(row monitorScanner) (Monitor, error) {
	var monitor Monitor
	var enabled int
	err := row.Scan(&monitor.ID, &monitor.Name, &monitor.Type, &monitor.Target, &monitor.Warning,
		&monitor.Critical, &monitor.IntervalSeconds, &monitor.RepeatMinutes, &monitor.CooldownMinutes,
		&monitor.Recipients, &enabled, &monitor.LastCheckedAt, &monitor.CreatedAt, &monitor.UpdatedAt)
	monitor.Enabled = enabled == 1
	return monitor, err
}

func (s *Store) ListMonitorAssignments(monitorID string) ([]MonitorAssignment, error) {
	rows, err := s.db.Query("SELECT monitor_id,scope,target FROM monitor_assignments WHERE monitor_id=?", monitorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assignments []MonitorAssignment
	for rows.Next() {
		var assignment MonitorAssignment
		if err := rows.Scan(&assignment.MonitorID, &assignment.Scope, &assignment.Target); err != nil {
			return nil, err
		}
		assignments = append(assignments, assignment)
	}
	return assignments, rows.Err()
}

func (s *Store) SetMonitorChecked(monitorID, checkedAt string) error {
	_, err := s.db.Exec("UPDATE monitors SET last_checked_at=? WHERE id=?", checkedAt, monitorID)
	return err
}

func (s *Store) GetMonitorState(monitorID, hostID string) (MonitorState, error) {
	var state MonitorState
	err := s.db.QueryRow(`SELECT monitor_id,host_id,status,message,checked_at,changed_at,last_notified
		FROM monitor_state WHERE monitor_id=? AND host_id=?`, monitorID, hostID).
		Scan(&state.MonitorID, &state.HostID, &state.Status, &state.Message, &state.CheckedAt,
			&state.ChangedAt, &state.LastNotified)
	return state, err
}

func (s *Store) UpsertMonitorState(state MonitorState) error {
	_, err := s.db.Exec(`INSERT INTO monitor_state(monitor_id,host_id,status,message,checked_at,changed_at,last_notified)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(monitor_id,host_id) DO UPDATE SET
			status=excluded.status, message=excluded.message, checked_at=excluded.checked_at,
			changed_at=excluded.changed_at, last_notified=excluded.last_notified`,
		state.MonitorID, state.HostID, state.Status, state.Message, state.CheckedAt, state.ChangedAt, state.LastNotified)
	return err
}

func (s *Store) ListMonitorStates(monitorID string) ([]MonitorState, error) {
	rows, err := s.db.Query(`SELECT monitor_id,host_id,status,message,checked_at,changed_at,last_notified
		FROM monitor_state WHERE monitor_id=? AND (host_id='' OR host_id IN (SELECT id FROM hosts))
		ORDER BY host_id`, monitorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []MonitorState
	for rows.Next() {
		var state MonitorState
		if err := rows.Scan(&state.MonitorID, &state.HostID, &state.Status, &state.Message,
			&state.CheckedAt, &state.ChangedAt, &state.LastNotified); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

// DeleteMonitorStates clears recorded per-host results for a monitor. It is
// used when a monitor is disabled so stale critical states do not remain
// visible after the operator turns the monitor off.
func (s *Store) DeleteMonitorStates(monitorID string) error {
	_, err := s.db.Exec("DELETE FROM monitor_state WHERE monitor_id=?", monitorID)
	return err
}

// DeleteMonitorState removes one host's recorded result from a monitor. It is
// used when an assignment change stops targeting that host.
func (s *Store) DeleteMonitorState(monitorID, hostID string) error {
	_, err := s.db.Exec("DELETE FROM monitor_state WHERE monitor_id=? AND host_id=?", monitorID, hostID)
	return err
}

func (s *Store) AddAlertEvent(event AlertEvent) error {
	emailed := 0
	if event.Emailed {
		emailed = 1
	}
	_, err := s.db.Exec(`INSERT INTO alert_events(monitor_id,host_id,status,subject,detail,created_at,emailed,error)
		VALUES(?,?,?,?,?,?,?,?)`, event.MonitorID, event.HostID, event.Status, event.Subject,
		event.Detail, event.CreatedAt, emailed, event.Error)
	return err
}

func (s *Store) ListAlertEvents(limit int) ([]AlertEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,monitor_id,host_id,status,subject,detail,created_at,emailed,error
		FROM alert_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AlertEvent
	for rows.Next() {
		var event AlertEvent
		var emailed int
		if err := rows.Scan(&event.ID, &event.MonitorID, &event.HostID, &event.Status, &event.Subject,
			&event.Detail, &event.CreatedAt, &emailed, &event.Error); err != nil {
			return nil, err
		}
		event.Emailed = emailed == 1
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) SaveServiceState(hostID string, failed, running []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM host_services WHERE host_id=?", hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	now := crypto.Now()
	seen := make(map[string]bool)
	for _, unit := range failed {
		if unit == "" || seen[unit] {
			continue
		}
		seen[unit] = true
		if _, err := tx.Exec("INSERT INTO host_services(host_id,unit,state,last_seen) VALUES(?,?,?,?)", hostID, unit, "failed", now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for _, unit := range running {
		if unit == "" || seen[unit] {
			continue
		}
		seen[unit] = true
		if _, err := tx.Exec("INSERT INTO host_services(host_id,unit,state,last_seen) VALUES(?,?,?,?)", hostID, unit, "running", now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetServiceState(hostID, unit string) (ServiceState, error) {
	var state ServiceState
	err := s.db.QueryRow("SELECT host_id,unit,state,last_seen FROM host_services WHERE host_id=? AND unit=?",
		hostID, unit).Scan(&state.HostID, &state.Unit, &state.State, &state.LastSeen)
	return state, err
}

func (s *Store) ListServiceStates(hostID string) ([]ServiceState, error) {
	rows, err := s.db.Query("SELECT host_id,unit,state,last_seen FROM host_services WHERE host_id=? ORDER BY unit", hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var states []ServiceState
	for rows.Next() {
		var state ServiceState
		if err := rows.Scan(&state.HostID, &state.Unit, &state.State, &state.LastSeen); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

// EnsureServiceBaseline records the first running-unit snapshot for a host. It
// deliberately does not add newly observed units on later collections. Use
// SyncServiceBaseline when automatic baseline expansion is enabled.
func (s *Store) EnsureServiceBaseline(hostID string, running []string) error {
	return s.syncServiceBaseline(hostID, running, false)
}

// SyncServiceBaseline records running units. With addNew it also adds units
// observed running for the first time, without changing existing exclusions or
// removing units that stopped running.
func (s *Store) SyncServiceBaseline(hostID string, running []string, addNew bool) error {
	return s.syncServiceBaseline(hostID, running, addNew)
}

func (s *Store) syncServiceBaseline(hostID string, running []string, addNew bool) error {
	if hostID == "" {
		return errors.New("host id is required")
	}
	if !addNew {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM host_service_baseline WHERE host_id=?", hostID).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	now := crypto.Now()
	seen := make(map[string]bool, len(running))
	for _, unit := range running {
		unit = strings.TrimSpace(unit)
		if unit == "" || seen[unit] {
			continue
		}
		seen[unit] = true
		if _, err := tx.Exec(`INSERT OR IGNORE INTO host_service_baseline
			(host_id,unit,state,expected,excluded,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
			hostID, unit, "running", 1, 0, now, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// SetServiceBaselineExcluded hides or restores a unit in the host baseline. A
// unit that is not yet tracked is inserted as expected so it can be restored
// later; excluding a failing unit must not require it to be in the original
// first snapshot.
func (s *Store) SetServiceBaselineExcluded(hostID, unit string, excluded bool) error {
	hostID = strings.TrimSpace(hostID)
	unit = strings.TrimSpace(unit)
	if hostID == "" || unit == "" {
		return errors.New("host id and unit are required")
	}
	flag := 0
	if excluded {
		flag = 1
	}
	result, err := s.db.Exec(`UPDATE host_service_baseline SET excluded=? WHERE host_id=? AND unit=?`, flag, hostID, unit)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		return nil
	}
	if !excluded {
		return sql.ErrNoRows
	}
	now := crypto.Now()
	_, err = s.db.Exec(`INSERT INTO host_service_baseline
		(host_id,unit,state,expected,excluded,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
		hostID, unit, "excluded", 1, 1, now, now)
	return err
}

// ResetServiceBaseline rebuilds the expected set from the currently running
// units while preserving explicit exclusions. Units that disappeared are
// removed; excluded rows remain so an exclusion survives a reset.
func (s *Store) ResetServiceBaseline(hostID string, running []string) error {
	if strings.TrimSpace(hostID) == "" {
		return errors.New("host id is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM host_service_baseline WHERE host_id=? AND excluded=0`, hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	now := crypto.Now()
	seen := make(map[string]bool, len(running))
	for _, unit := range running {
		unit = strings.TrimSpace(unit)
		if unit == "" || seen[unit] {
			continue
		}
		seen[unit] = true
		if _, err := tx.Exec(`INSERT OR IGNORE INTO host_service_baseline
			(host_id,unit,state,expected,excluded,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
			hostID, unit, "running", 1, 0, now, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListServiceBaseline(hostID string) ([]ServiceBaseline, error) {
	rows, err := s.db.Query(`SELECT host_id,unit,state,expected,excluded,first_seen,last_seen
		FROM host_service_baseline WHERE host_id=? ORDER BY unit`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var baseline []ServiceBaseline
	for rows.Next() {
		var item ServiceBaseline
		var expected, excluded int
		if err := rows.Scan(&item.HostID, &item.Unit, &item.State, &expected, &excluded,
			&item.FirstSeen, &item.LastSeen); err != nil {
			return nil, err
		}
		item.Expected = expected == 1
		item.Excluded = excluded == 1
		baseline = append(baseline, item)
	}
	return baseline, rows.Err()
}
