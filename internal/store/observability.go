package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/RogerBergling/hibp/internal/crypto"
)

// SystemInfoSnapshot is the latest read-only host inventory.
type SystemInfoSnapshot struct {
	HostID      string `json:"host_id"`
	CollectedAt string `json:"collected_at"`
	PayloadJSON string `json:"payload_json"`
}

// MetricSample is one point in the host metrics history.
type MetricSample struct {
	CollectedAt   string  `json:"collected_at"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	SwapPercent   float64 `json:"swap_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	UptimeSeconds uint64  `json:"uptime_seconds"`
}

// DockerProject is a cached Compose project under a host.
type DockerProject struct {
	HostID      string `json:"host_id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	ConfigFiles string `json:"config_files"`
	WorkingDir  string `json:"working_dir"`
	LastSeen    string `json:"last_seen"`
}

// DockerContainer is a cached container under a host.
type DockerContainer struct {
	HostID      string `json:"host_id"`
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Project     string `json:"project"`
	Service     string `json:"service"`
	Image       string `json:"image"`
	State       string `json:"state"`
	Status      string `json:"status"`
	Health      string `json:"health"`
	Ports       string `json:"ports"`
	CreatedAt   string `json:"created_at"`
	LastSeen    string `json:"last_seen"`
}

// DockerProjectCheck is the latest pull/compare result for a Compose project.
type DockerProjectCheck struct {
	HostID    string `json:"host_id"`
	Project   string `json:"project"`
	Status    string `json:"status"`
	CheckedAt string `json:"checked_at"`
	Summary   string `json:"summary"`
	Error     string `json:"error,omitempty"`
}

func (s *Store) SaveDockerProjectCheck(check DockerProjectCheck) error {
	if check.HostID == "" || check.Project == "" {
		return errors.New("host id and Docker project are required")
	}
	if check.CheckedAt == "" {
		check.CheckedAt = crypto.Now()
	}
	_, err := s.db.Exec(`INSERT INTO docker_project_checks(host_id,project,status,checked_at,summary,error)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(host_id,project) DO UPDATE SET
			status=excluded.status, checked_at=excluded.checked_at,
			summary=excluded.summary, error=excluded.error`,
		check.HostID, check.Project, check.Status, check.CheckedAt, check.Summary, check.Error)
	return err
}

func (s *Store) ListDockerProjectChecks(hostID string) ([]DockerProjectCheck, error) {
	rows, err := s.db.Query(`SELECT host_id,project,status,checked_at,summary,error
		FROM docker_project_checks WHERE host_id=? ORDER BY project`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var checks []DockerProjectCheck
	for rows.Next() {
		var check DockerProjectCheck
		if err := rows.Scan(&check.HostID, &check.Project, &check.Status, &check.CheckedAt,
			&check.Summary, &check.Error); err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, rows.Err()
}

func (s *Store) SaveSystemInfo(hostID, collectedAt, payloadJSON string) error {
	if hostID == "" || payloadJSON == "" {
		return errors.New("host id and system info payload are required")
	}
	_, err := s.db.Exec(`INSERT INTO host_system_info(host_id,collected_at,payload_json)
		VALUES(?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET collected_at=excluded.collected_at, payload_json=excluded.payload_json`,
		hostID, collectedAt, payloadJSON)
	return err
}

func (s *Store) GetSystemInfo(hostID string) (SystemInfoSnapshot, error) {
	var snapshot SystemInfoSnapshot
	err := s.db.QueryRow("SELECT host_id,collected_at,payload_json FROM host_system_info WHERE host_id=?", hostID).
		Scan(&snapshot.HostID, &snapshot.CollectedAt, &snapshot.PayloadJSON)
	return snapshot, err
}

func (s *Store) SaveMetrics(hostID string, sample MetricSample) error {
	if hostID == "" {
		return errors.New("host id is required")
	}
	if sample.CollectedAt == "" {
		sample.CollectedAt = crypto.Now()
	}
	_, err := s.db.Exec(`INSERT INTO host_metrics(host_id,collected_at,cpu_percent,memory_percent,swap_percent,
		disk_percent,load1,load5,load15,uptime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		hostID, sample.CollectedAt, sample.CPUPercent, sample.MemoryPercent, sample.SwapPercent,
		sample.DiskPercent, sample.Load1, sample.Load5, sample.Load15, sample.UptimeSeconds)
	return err
}

func (s *Store) ListMetrics(hostID string, limit int) ([]MetricSample, error) {
	if limit <= 0 || limit > 5000 {
		limit = 288
	}
	rows, err := s.db.Query(`SELECT collected_at,cpu_percent,memory_percent,swap_percent,disk_percent,
		load1,load5,load15,uptime_seconds FROM host_metrics WHERE host_id=? ORDER BY id DESC LIMIT ?`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := make([]MetricSample, 0, limit)
	for rows.Next() {
		var sample MetricSample
		if err := rows.Scan(&sample.CollectedAt, &sample.CPUPercent, &sample.MemoryPercent,
			&sample.SwapPercent, &sample.DiskPercent, &sample.Load1, &sample.Load5, &sample.Load15,
			&sample.UptimeSeconds); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	// Return oldest first so the chart code can render left-to-right.
	for left, right := 0, len(samples)-1; left < right; left, right = left+1, right-1 {
		samples[left], samples[right] = samples[right], samples[left]
	}
	return samples, rows.Err()
}

func (s *Store) DeleteMetricsBefore(cutoff string) error {
	_, err := s.db.Exec("DELETE FROM host_metrics WHERE collected_at < ?", cutoff)
	return err
}

func (s *Store) DeleteMetricsBeforeForHost(hostID, cutoff string) error {
	_, err := s.db.Exec("DELETE FROM host_metrics WHERE host_id=? AND collected_at < ?", hostID, cutoff)
	return err
}

// ListMetricsSince returns metric samples at or after the supplied RFC3339
// timestamp, oldest first. The limit is a safety cap for very dense collection
// intervals; when it is reached, the newest samples in the range are kept.
func (s *Store) ListMetricsSince(hostID, since string, limit int) ([]MetricSample, error) {
	if limit <= 0 || limit > 100000 {
		limit = 100000
	}
	rows, err := s.db.Query(`SELECT collected_at,cpu_percent,memory_percent,swap_percent,disk_percent,
		load1,load5,load15,uptime_seconds FROM (
			SELECT id,collected_at,cpu_percent,memory_percent,swap_percent,disk_percent,
				load1,load5,load15,uptime_seconds FROM host_metrics
			WHERE host_id=? AND collected_at>=? ORDER BY id DESC LIMIT ?
		) ORDER BY id ASC`, hostID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := make([]MetricSample, 0, 1024)
	for rows.Next() {
		var sample MetricSample
		if err := rows.Scan(&sample.CollectedAt, &sample.CPUPercent, &sample.MemoryPercent,
			&sample.SwapPercent, &sample.DiskPercent, &sample.Load1, &sample.Load5,
			&sample.Load15, &sample.UptimeSeconds); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

func (s *Store) SaveDockerInventory(hostID string, projects []DockerProject, containers []DockerContainer) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM docker_containers WHERE host_id=?", hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec("DELETE FROM docker_projects WHERE host_id=?", hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	now := crypto.Now()
	for _, project := range projects {
		if _, err := tx.Exec(`INSERT INTO docker_projects(host_id,name,status,config_files,working_dir,last_seen)
			VALUES(?,?,?,?,?,?)`, hostID, project.Name, project.Status, project.ConfigFiles, project.WorkingDir, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	for _, container := range containers {
		if _, err := tx.Exec(`INSERT INTO docker_containers(host_id,container_id,name,project,service,image,
			state,status,health,ports,created_at,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			hostID, container.ContainerID, container.Name, container.Project, container.Service, container.Image,
			container.State, container.Status, container.Health, container.Ports, container.CreatedAt, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetDockerInventory(hostID string) ([]DockerProject, []DockerContainer, error) {
	projectRows, err := s.db.Query(`SELECT host_id,name,status,config_files,working_dir,last_seen
		FROM docker_projects WHERE host_id=? ORDER BY name`, hostID)
	if err != nil {
		return nil, nil, err
	}
	var projects []DockerProject
	for projectRows.Next() {
		var project DockerProject
		if err := projectRows.Scan(&project.HostID, &project.Name, &project.Status, &project.ConfigFiles,
			&project.WorkingDir, &project.LastSeen); err != nil {
			projectRows.Close()
			return nil, nil, err
		}
		projects = append(projects, project)
	}
	if err := projectRows.Close(); err != nil {
		return nil, nil, err
	}
	containerRows, err := s.db.Query(`SELECT host_id,container_id,name,project,service,image,state,status,
		health,ports,created_at,last_seen FROM docker_containers WHERE host_id=? ORDER BY project,name`, hostID)
	if err != nil {
		return nil, nil, err
	}
	defer containerRows.Close()
	var containers []DockerContainer
	for containerRows.Next() {
		var container DockerContainer
		if err := containerRows.Scan(&container.HostID, &container.ContainerID, &container.Name,
			&container.Project, &container.Service, &container.Image, &container.State, &container.Status,
			&container.Health, &container.Ports, &container.CreatedAt, &container.LastSeen); err != nil {
			return nil, nil, err
		}
		containers = append(containers, container)
	}
	return projects, containers, containerRows.Err()
}

func (s *Store) SetSetting(scope, key, value string) error {
	if scope == "" || key == "" {
		return errors.New("setting scope and key are required")
	}
	_, err := s.db.Exec(`INSERT INTO settings(scope,key,value,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		scope, key, value, crypto.Now())
	return err
}

func (s *Store) GetSetting(scope, key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE scope=? AND key=?", scope, key).Scan(&value)
	return value, err
}

func (s *Store) DeleteSetting(scope, key string) error {
	_, err := s.db.Exec("DELETE FROM settings WHERE scope=? AND key=?", scope, key)
	return err
}

func (s *Store) ListSettings(scope string) (map[string]string, error) {
	rows, err := s.db.Query("SELECT key,value FROM settings WHERE scope=?", scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	settings := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		settings[key] = value
	}
	return settings, rows.Err()
}

// ResolveSetting applies host override -> fleet default -> built-in default.
func (s *Store) ResolveSetting(hostID, key, defaultValue string) string {
	if hostID != "" {
		if value, err := s.GetSetting("host:"+hostID, key); err == nil {
			return value
		}
	}
	if value, err := s.GetSetting("fleet", key); err == nil {
		return value
	}
	return defaultValue
}

func IsNoSetting(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

func CleanScope(scope string) string {
	return strings.TrimSpace(scope)
}
