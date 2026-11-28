package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

type Monitor struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Type               string              `json:"type"`
	Target             string              `json:"target"`
	Warning            float64             `json:"warning"`
	Critical           float64             `json:"critical"`
	InsecureSkipVerify bool                `json:"insecure_skip_verify"`
	IntervalSeconds    int                 `json:"interval_seconds"`
	RepeatMinutes      int                 `json:"repeat_minutes"`
	CooldownMinutes    int                 `json:"cooldown_minutes"`
	Recipients         string              `json:"recipients"`
	Enabled            bool                `json:"enabled"`
	LastCheckedAt      string              `json:"last_checked_at"`
	CreatedAt          string              `json:"created_at"`
	UpdatedAt          string              `json:"updated_at"`
	Assignments        []MonitorAssignment `json:"assignments,omitempty"`
	States             []MonitorState      `json:"states,omitempty"`
}

type MonitorAssignment struct {
	MonitorID string `json:"monitor_id"`
	Scope     string `json:"scope"`
	Target    string `json:"target"`
}

type MonitorState struct {
	MonitorID           string `json:"monitor_id"`
	HostID              string `json:"host_id"`
	Status              string `json:"status"`
	Message             string `json:"message"`
	CheckedAt           string `json:"checked_at"`
	ChangedAt           string `json:"changed_at"`
	LastNotified        string `json:"last_notified"`
	AcknowledgedAt      string `json:"acknowledged_at,omitempty"`
	AcknowledgedBy      string `json:"acknowledged_by,omitempty"`
	AcknowledgementNote string `json:"acknowledgement_note,omitempty"`
	AcknowledgedStatus  string `json:"acknowledged_status,omitempty"`
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

const baselineDefaultExclusionsKey = "monitor.service_baseline.default_exclusions"
const baselineDefaultExclusionsVersion = "2"

// baselineDefaultExcludedUnits are units that are commonly started on demand,
// by a timer, or during boot and are not expected to stay running. Excluding
// them avoids repeated baseline alerts for packagekit, timedated, fstrim and
// similar transient services. Operators can include any unit explicitly from
// the host Services tab.
var baselineDefaultExcludedUnits = map[string]bool{
	"accounts-daemon.service":          true,
	"apt-daily.service":                true,
	"apt-daily-upgrade.service":        true,
	"apt-news.service":                 true,
	"colord.service":                   true,
	"dpkg-db-backup.service":           true,
	"e2scrub_all.service":              true,
	"e2scrub_reap.service":             true,
	"fstrim.service":                   true,
	"fwupd.service":                    true,
	"geoclue.service":                  true,
	"iio-sensor-proxy.service":         true,
	"logrotate.service":                true,
	"man-db.service":                   true,
	"motd-news.service":                true,
	"packagekit.service":               true,
	"snapd.autoimport.service":         true,
	"snapd.core-fixup.service":         true,
	"snapd.refresh.service":            true,
	"snapd.seeded.service":             true,
	"switcheroo-control.service":       true,
	"systemd-hostnamed.service":        true,
	"systemd-localed.service":          true,
	"systemd-timedated.service":        true,
	"systemd-tmpfiles-clean.service":   true,
	"udisks2.service":                  true,
	"upower.service":                   true,
	"update-notifier-download.service": true,
	"ua-timer.service":                 true,
}

var baselineDefaultExcludedPrefixes = []string{
	"check-mk-agent@",
	"e2scrub@",
	"systemd-backlight@",
	"systemd-fsck@",
}

func baselineDefaultExcluded(unit string) bool {
	if baselineDefaultExcludedUnits[unit] {
		return true
	}
	for _, prefix := range baselineDefaultExcludedPrefixes {
		if strings.HasPrefix(unit, prefix) {
			return true
		}
	}
	return false
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
	insecureSkipVerify := 0
	if monitor.InsecureSkipVerify {
		insecureSkipVerify = 1
	}
	if _, err := tx.Exec(`INSERT INTO monitors(id,name,type,target,warning,critical,insecure_skip_verify,interval_seconds,
		repeat_minutes,cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, monitor.ID, monitor.Name, monitor.Type, monitor.Target,
		monitor.Warning, monitor.Critical, insecureSkipVerify, monitor.IntervalSeconds, monitor.RepeatMinutes,
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
	insecureSkipVerify := 0
	if monitor.InsecureSkipVerify {
		insecureSkipVerify = 1
	}
	res, err := tx.Exec(`UPDATE monitors SET name=?,type=?,target=?,warning=?,critical=?,insecure_skip_verify=?,interval_seconds=?,
		repeat_minutes=?,cooldown_minutes=?,recipients=?,enabled=?,updated_at=? WHERE id=?`,
		monitor.Name, monitor.Type, monitor.Target, monitor.Warning, monitor.Critical,
		insecureSkipVerify, monitor.IntervalSeconds, monitor.RepeatMinutes, monitor.CooldownMinutes, monitor.Recipients,
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
	row := s.db.QueryRow(`SELECT id,name,type,target,warning,critical,insecure_skip_verify,interval_seconds,repeat_minutes,
		cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at FROM monitors WHERE id=?`, id)
	return scanMonitor(row)
}

func (s *Store) ListMonitors() ([]Monitor, error) {
	rows, err := s.db.Query(`SELECT id,name,type,target,warning,critical,insecure_skip_verify,interval_seconds,repeat_minutes,
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
	var enabled, insecureSkipVerify int
	err := row.Scan(&monitor.ID, &monitor.Name, &monitor.Type, &monitor.Target, &monitor.Warning,
		&monitor.Critical, &insecureSkipVerify, &monitor.IntervalSeconds, &monitor.RepeatMinutes, &monitor.CooldownMinutes,
		&monitor.Recipients, &enabled, &monitor.LastCheckedAt, &monitor.CreatedAt, &monitor.UpdatedAt)
	monitor.Enabled = enabled == 1
	monitor.InsecureSkipVerify = insecureSkipVerify == 1
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
	err := s.db.QueryRow(`SELECT monitor_id,host_id,status,message,checked_at,changed_at,last_notified,
		acknowledged_at,acknowledged_by,acknowledgement_note,acknowledged_status
		FROM monitor_state WHERE monitor_id=? AND host_id=?`, monitorID, hostID).
		Scan(&state.MonitorID, &state.HostID, &state.Status, &state.Message, &state.CheckedAt,
			&state.ChangedAt, &state.LastNotified, &state.AcknowledgedAt, &state.AcknowledgedBy,
			&state.AcknowledgementNote, &state.AcknowledgedStatus)
	return state, err
}

func (s *Store) UpsertMonitorState(state MonitorState) error {
	_, err := s.db.Exec(`INSERT INTO monitor_state(monitor_id,host_id,status,message,checked_at,changed_at,last_notified,
		acknowledged_at,acknowledged_by,acknowledgement_note,acknowledged_status)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(monitor_id,host_id) DO UPDATE SET
			status=excluded.status, message=excluded.message, checked_at=excluded.checked_at,
			changed_at=excluded.changed_at, last_notified=excluded.last_notified,
			acknowledged_at=excluded.acknowledged_at, acknowledged_by=excluded.acknowledged_by,
			acknowledgement_note=excluded.acknowledgement_note, acknowledged_status=excluded.acknowledged_status`,
		state.MonitorID, state.HostID, state.Status, state.Message, state.CheckedAt, state.ChangedAt, state.LastNotified,
		state.AcknowledgedAt, state.AcknowledgedBy, state.AcknowledgementNote, state.AcknowledgedStatus)
	return err
}

// AcknowledgeMonitorStates marks current non-OK alerts as acknowledged without
// changing their status. An empty hostID acknowledges every non-OK host state
// for the monitor.
func (s *Store) AcknowledgeMonitorStates(monitorID, hostID, actor, note, at string) (int64, error) {
	query := `UPDATE monitor_state SET acknowledged_at=?, acknowledged_by=?,
		acknowledgement_note=?, acknowledged_status=status
		WHERE monitor_id=? AND status<>'ok'`
	args := []any{at, actor, note, monitorID}
	if hostID != "" {
		query += " AND host_id=?"
		args = append(args, hostID)
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClearMonitorAcknowledgements removes acknowledgements. An empty hostID clears
// every host state for the monitor.
func (s *Store) ClearMonitorAcknowledgements(monitorID, hostID string) (int64, error) {
	query := `UPDATE monitor_state SET acknowledged_at='', acknowledged_by='',
		acknowledgement_note='', acknowledged_status='' WHERE monitor_id=?`
	args := []any{monitorID}
	if hostID != "" {
		query += " AND host_id=?"
		args = append(args, hostID)
	}
	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) ListMonitorStates(monitorID string) ([]MonitorState, error) {
	rows, err := s.db.Query(`SELECT monitor_id,host_id,status,message,checked_at,changed_at,last_notified,
		acknowledged_at,acknowledged_by,acknowledgement_note,acknowledged_status
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
			&state.CheckedAt, &state.ChangedAt, &state.LastNotified, &state.AcknowledgedAt,
			&state.AcknowledgedBy, &state.AcknowledgementNote, &state.AcknowledgedStatus); err != nil {
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

// ClearAlertEvents deletes alert delivery history. Monitor state and audit
// entries are retained; the caller records the clear action in the audit log.
func (s *Store) ClearAlertEvents() (int64, error) {
	result, err := s.db.Exec("DELETE FROM alert_events")
	if err != nil {
		return 0, err
	}
	deleted, _ := result.RowsAffected()
	return deleted, nil
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
// deliberately does not add newly observed units on later collections. Default
// transient-unit exclusions are still applied once to an existing baseline.
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
	appliedVersion, _ := s.GetSetting("host:"+hostID, baselineDefaultExclusionsKey)
	applyDefaults := appliedVersion != baselineDefaultExclusionsVersion

	var existing int
	if !addNew {
		if err := s.db.QueryRow("SELECT COUNT(*) FROM host_service_baseline WHERE host_id=?", hostID).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 && !applyDefaults {
			return nil
		}
	}
	insert := addNew || existing == 0

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	now := crypto.Now()
	if applyDefaults {
		if err := applyBaselineDefaultExclusions(tx, hostID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if insert {
		seen := make(map[string]bool, len(running))
		for _, unit := range running {
			unit = strings.TrimSpace(unit)
			if unit == "" || seen[unit] {
				continue
			}
			seen[unit] = true
			excluded := 0
			if baselineDefaultExcluded(unit) {
				excluded = 1
			}
			if _, err := tx.Exec(`INSERT OR IGNORE INTO host_service_baseline
				(host_id,unit,state,expected,excluded,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)`,
				hostID, unit, "running", 1, excluded, now, now); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if applyDefaults {
		if err := s.SetSetting("host:"+hostID, baselineDefaultExclusionsKey, baselineDefaultExclusionsVersion); err != nil {
			return err
		}
	}
	return nil
}

// ApplyServiceBaselineDefaultExclusions applies the built-in transient-unit
// exclusion list once per host. It is safe to call frequently; the version
// setting makes it a no-op after the first application. It lets hosts with an
// existing baseline adopt new default exclusions before the next collection.
func (s *Store) ApplyServiceBaselineDefaultExclusions(hostID string) error {
	if hostID == "" {
		return errors.New("host id is required")
	}
	appliedVersion, _ := s.GetSetting("host:"+hostID, baselineDefaultExclusionsKey)
	if appliedVersion == baselineDefaultExclusionsVersion {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := applyBaselineDefaultExclusions(tx, hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.SetSetting("host:"+hostID, baselineDefaultExclusionsKey, baselineDefaultExclusionsVersion)
}

func applyBaselineDefaultExclusions(tx *sql.Tx, hostID string) error {
	rows, err := tx.Query(`SELECT unit FROM host_service_baseline WHERE host_id=? AND excluded=0`, hostID)
	if err != nil {
		return err
	}
	var units []string
	for rows.Next() {
		var unit string
		if err := rows.Scan(&unit); err != nil {
			_ = rows.Close()
			return err
		}
		units = append(units, unit)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, unit := range units {
		if !baselineDefaultExcluded(unit) {
			continue
		}
		if _, err := tx.Exec(`UPDATE host_service_baseline SET excluded=1 WHERE host_id=? AND unit=?`, hostID, unit); err != nil {
			return err
		}
	}
	return nil
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
