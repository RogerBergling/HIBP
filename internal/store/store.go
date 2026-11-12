// Package store owns the encrypted SQLCipher database, migrations, and audit chain.
package store

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/buildinfo"
	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
)

const applicationID = 1212760656 // 0x48494250 ("HIBP")

//go:embed migrations/*.sql
var migrationFS embed.FS

// Options controls database creation and test-friendly KDF parameters.
type Options struct {
	Create     bool
	KDFTime    uint32
	KDFMemory  uint32
	KDFThreads uint8
}

// DefaultOptions returns the production KDF parameters.
func DefaultOptions() Options {
	return Options{
		Create:     false,
		KDFTime:    crypto.DefaultTime,
		KDFMemory:  crypto.DefaultMemory,
		KDFThreads: crypto.DefaultThreads,
	}
}

// Host is a managed Linux host.
type Host struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Address              string   `json:"address"`
	Port                 int      `json:"port"`
	Username             string   `json:"username"`
	AuthType             string   `json:"auth_type"`
	KeyPath              string   `json:"key_path"`
	OSFamily             string   `json:"os_family"`
	OSVersion            string   `json:"os_version"`
	Status               string   `json:"status"`
	Tags                 string   `json:"tags"`
	GroupName            string   `json:"group_name"`
	CMDBCIID             string   `json:"cmdb_ci_id"`
	CreatedAt            string   `json:"created_at"`
	UpdatedAt            string   `json:"updated_at"`
	DockerProjectCount   int      `json:"docker_project_count"`
	DockerContainerCount int      `json:"docker_container_count"`
	Facts                *Facts   `json:"facts,omitempty"`
	TrustedKey           *HostKey `json:"trusted_key,omitempty"`
}

// Facts is the latest collected host state.
type Facts struct {
	CollectedAt    string         `json:"collected_at"`
	UptimeSeconds  int64          `json:"uptime_seconds"`
	BootTime       string         `json:"boot_time"`
	Kernel         string         `json:"kernel"`
	OSPrettyName   string         `json:"os_pretty_name"`
	PackageManager string         `json:"package_manager"`
	RebootRequired bool           `json:"reboot_required"`
	DiskFreeBytes  int64          `json:"disk_free_bytes"`
	TimeSyncOK     bool           `json:"time_sync_ok"`
	PendingUpdates int            `json:"pending_updates"`
	Agent          buildinfo.Info `json:"agent"`
}

// HostKey is a trusted SSH host key.
type HostKey struct {
	HostID      string `json:"host_id"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
}

// AuditEntry is one link in the tamper-evident audit chain.
type AuditEntry struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Detail     string `json:"detail"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
}

// Store is an open encrypted database.
type Store struct {
	db   *sql.DB
	path string
	key  []byte
}

// Open opens or creates an encrypted HIBP database.
func Open(path string, passphrase []byte, opts Options) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if opts.KDFTime == 0 {
		opts.KDFTime = crypto.DefaultTime
	}
	if opts.KDFMemory == 0 {
		opts.KDFMemory = crypto.DefaultMemory
	}
	if opts.KDFThreads == 0 {
		opts.KDFThreads = crypto.DefaultThreads
	}

	var key []byte
	if opts.Create {
		if _, err := os.Stat(abs); err == nil {
			return nil, fmt.Errorf("database already exists: %s", abs)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if _, err := os.Stat(crypto.SidecarPath(abs)); err == nil {
			return nil, fmt.Errorf("sidecar already exists: %s", crypto.SidecarPath(abs))
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		_, key, err = crypto.CreateSidecarWithParams(abs, passphrase, opts.KDFTime, opts.KDFMemory, opts.KDFThreads)
		if err != nil {
			return nil, err
		}
	} else {
		sidecar, err := crypto.ReadSidecar(abs)
		if err != nil {
			return nil, err
		}
		key, err = crypto.DeriveKey(passphrase, sidecar)
		if err != nil {
			return nil, err
		}
	}

	db, err := openSQLCipher(abs, key)
	if err != nil {
		crypto.Zero(key)
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		crypto.Zero(key)
		return nil, fmt.Errorf("invalid passphrase or not an HIBP database: %w", err)
	}
	s := &Store{db: db, path: abs, key: key}
	var appID int
	_ = s.db.QueryRow("PRAGMA application_id").Scan(&appID)
	if appID != 0 && appID != applicationID {
		_ = s.Close()
		return nil, fmt.Errorf("not an HIBP database (application_id=%d)", appID)
	}
	if err := s.applyPragmas(); err != nil {
		_ = s.Close()
		if opts.Create {
			_ = os.Remove(abs)
			_ = os.Remove(crypto.SidecarPath(abs))
		}
		return nil, err
	}
	if !opts.Create {
		if _, err := s.preMigrationBackup(); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("automatic pre-migration backup: %w", err)
		}
	}
	if err := s.migrate(); err != nil {
		_ = s.Close()
		if opts.Create {
			_ = os.Remove(abs)
			_ = os.Remove(crypto.SidecarPath(abs))
		}
		return nil, err
	}
	_ = os.Chmod(abs, 0o600)
	_ = os.Chmod(abs+"-wal", 0o600)
	_ = os.Chmod(abs+"-shm", 0o600)
	return s, nil
}

func (s *Store) applyPragmas() error {
	statements := []string{
		"PRAGMA foreign_keys=ON",
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA secure_delete=ON",
		"PRAGMA temp_store=MEMORY",
		"PRAGMA trusted_schema=OFF",
		"PRAGMA cipher_memory_security=ON",
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("apply %s: %w", statement, err)
		}
	}
	return nil
}

type migrationFile struct {
	version  int
	name     string
	payload  []byte
	checksum string
}

func readMigrations() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	files := make([]migrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			return nil, err
		}
		payload, err := fs.ReadFile(migrationFS, "migrations/"+entry.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(payload)
		files = append(files, migrationFile{
			version: version, name: entry.Name(), payload: payload, checksum: hex.EncodeToString(sum[:]),
		})
	}
	return files, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	files, err := readMigrations()
	if err != nil {
		return err
	}
	embeddedMax := 0
	for _, file := range files {
		if file.version > embeddedMax {
			embeddedMax = file.version
		}
	}
	var appliedMax int
	if err := s.db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&appliedMax); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if appliedMax > embeddedMax {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d); upgrade HIBP before opening this database", appliedMax, embeddedMax)
	}

	maxVersion := 0
	for _, file := range files {
		var existing string
		err = s.db.QueryRow("SELECT checksum FROM schema_migrations WHERE version=?", file.version).Scan(&existing)
		if err == nil {
			if existing != file.checksum {
				return fmt.Errorf("migration %d checksum mismatch", file.version)
			}
			if file.version > maxVersion {
				maxVersion = file.version
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read migration %d: %w", file.version, err)
		}

		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(file.payload)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", file.version, err)
		}
		if _, err := tx.Exec(
			"INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES(?,?,?,?)",
			file.version, file.name, file.checksum, crypto.Now(),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if file.version > maxVersion {
			maxVersion = file.version
		}
	}

	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA application_id=%d", applicationID)); err != nil {
		return err
	}
	if maxVersion > 0 {
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", maxVersion)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) pendingMigrations() ([]migrationFile, error) {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	files, err := readMigrations()
	if err != nil {
		return nil, err
	}
	var pending []migrationFile
	for _, file := range files {
		var existing int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=?", file.version).Scan(&existing); err != nil {
			return nil, err
		}
		if existing == 0 {
			pending = append(pending, file)
		}
	}
	return pending, nil
}

// managedBackupPattern matches files created by HIBP's timestamped backup
// paths. It deliberately excludes arbitrary *.bac files so retention cannot
// delete an operator-owned file.
var managedBackupPattern = regexp.MustCompile(`^hibp-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\.bac$|^[A-Za-z0-9._ -]+-pre-migration-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}(-[0-9]+)?\.bac$`)

// BackupConfig returns the configured backup directory and retention count.
// An empty directory means the database directory. Invalid or missing settings
// fall back to the safe defaults.
func (s *Store) BackupConfig() (string, int) {
	directory := ""
	retention := 3
	var value string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE scope='fleet' AND key='backup.directory'").Scan(&value); err == nil {
		directory = strings.TrimSpace(value)
		if directory != "" && !filepath.IsAbs(directory) {
			directory = ""
		}
	}
	if err := s.db.QueryRow("SELECT value FROM settings WHERE scope='fleet' AND key='backup.retention_count'").Scan(&value); err == nil {
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && parsed >= 1 && parsed <= 100 {
			retention = parsed
		}
	}
	return directory, retention
}

// pruneManagedBackups keeps the newest retained timestamped backups in dir.
// Only names HIBP generates are considered; arbitrary *.bac files are left
// alone. A sidecar is removed with its database file.
func pruneManagedBackups(dir string, retention int) error {
	if retention < 1 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		if !managedBackupPattern.MatchString(name) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		candidates = append(candidates, candidate{path: filepath.Join(dir, name), modTime: info.ModTime()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].path > candidates[j].path
		}
		return candidates[i].modTime.After(candidates[j].modTime)
	})
	if len(candidates) <= retention {
		return nil
	}
	for _, old := range candidates[retention:] {
		if err := os.Remove(old.path); err != nil {
			slog.Warn("prune backup", "path", old.path, "error", err)
			continue
		}
		if err := os.Remove(crypto.SidecarPath(old.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("prune backup sidecar", "path", crypto.SidecarPath(old.path), "error", err)
		}
	}
	return nil
}

// preMigrationBackup writes and verifies a timestamped encrypted backup before
// any pending schema migration is applied. A failed backup aborts the upgrade.
func (s *Store) preMigrationBackup() (string, error) {
	pending, err := s.pendingMigrations()
	if err != nil || len(pending) == 0 {
		return "", err
	}
	directory, retention := s.BackupConfig()
	if directory == "" {
		directory = filepath.Dir(s.path)
	}
	base := strings.TrimSuffix(filepath.Base(s.path), filepath.Ext(s.path))
	if base == "" {
		base = "hibp"
	}
	stamp := time.Now().UTC().Format("2006-01-02-150405")
	path := filepath.Join(directory, base+"-pre-migration-"+stamp+".bac")
	for suffix := 1; ; suffix++ {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return "", err
		}
		path = filepath.Join(directory, fmt.Sprintf("%s-pre-migration-%s-%d.bac", base, stamp, suffix))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := backupDatabase(path, s.db); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := copyFile(crypto.SidecarPath(s.path), crypto.SidecarPath(path)); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(crypto.SidecarPath(path))
		return "", err
	}
	if err := verifyBackup(path, s.key); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(crypto.SidecarPath(path))
		return "", err
	}
	if err := pruneManagedBackups(directory, retention); err != nil {
		slog.Warn("pre-migration backup retention", "directory", directory, "error", err)
	}
	slog.Info("created automatic pre-migration backup", "path", path, "pending_migrations", len(pending))
	return path, nil
}

func migrationVersion(name string) (int, error) {
	part := strings.SplitN(name, "_", 2)[0]
	version, err := strconv.Atoi(part)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("invalid migration name %q", name)
	}
	return version, nil
}

// Close closes the database and zeroizes the key.
func (s *Store) Close() error {
	var err error
	if s.db != nil {
		err = s.db.Close()
		s.db = nil
	}
	crypto.Zero(s.key)
	s.key = nil
	return err
}

// Path returns the database path.
func (s *Store) Path() string { return s.path }

// ValidateHost exposes host validation to the API layer.
func ValidateHost(host Host) error {
	return validateHost(host)
}

func validateHost(host Host) error {
	if strings.TrimSpace(host.Name) == "" {
		return errors.New("host name is required")
	}
	if strings.TrimSpace(host.Address) == "" {
		return errors.New("address is required")
	}
	if host.Port == 0 {
		host.Port = 22
	}
	if host.Port < 1 || host.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if strings.TrimSpace(host.Username) == "" {
		return errors.New("username is required")
	}
	authType := strings.TrimSpace(host.AuthType)
	if authType == "" {
		authType = "key"
	}
	switch authType {
	case "key", "password":
	default:
		return errors.New("auth_type must be key or password; ssh-agent and SSH certificate authentication are not supported")
	}
	if authType == "key" && strings.TrimSpace(host.KeyPath) == "" {
		return errors.New("key_path is required for key authentication")
	}
	return nil
}

// CreateHost inserts a host and an audit entry atomically.
func (s *Store) CreateHost(host Host) (Host, error) {
	return s.CreateHostAs("local", host)
}

// CreateHostAs inserts a host and records the supplied audit actor.
func (s *Store) CreateHostAs(actor string, host Host) (Host, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "local"
	}
	if err := validateHost(host); err != nil {
		return Host{}, err
	}
	if host.Port == 0 {
		host.Port = 22
	}
	if host.AuthType == "" {
		host.AuthType = "key"
	}
	if host.Status == "" {
		host.Status = "unknown"
	}
	now := crypto.Now()
	host.ID = uuid.NewString()
	host.CreatedAt = now
	host.UpdatedAt = now

	tx, err := s.db.Begin()
	if err != nil {
		return Host{}, err
	}
	_, err = tx.Exec(`INSERT INTO hosts
		(id,name,address,port,username,auth_type,key_path,os_family,os_version,status,tags,group_name,cmdb_ci_id,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		host.ID, host.Name, host.Address, host.Port, host.Username, host.AuthType, host.KeyPath,
		host.OSFamily, host.OSVersion, host.Status, host.Tags, host.GroupName, host.CMDBCIID,
		host.CreatedAt, host.UpdatedAt)
	if err != nil {
		_ = tx.Rollback()
		return Host{}, err
	}
	if err := s.addAuditTx(tx, actor, "create", "host", host.ID, host.Name+" ("+host.Address+")"); err != nil {
		_ = tx.Rollback()
		return Host{}, err
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return host, nil
}

// UpdateHost updates editable host fields.
func (s *Store) UpdateHost(host Host) (Host, error) {
	return s.UpdateHostAs("local", host)
}

// UpdateHostAs updates editable host fields and records the supplied actor.
func (s *Store) UpdateHostAs(actor string, host Host) (Host, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "local"
	}
	if err := validateHost(host); err != nil {
		return Host{}, err
	}
	if host.Port == 0 {
		host.Port = 22
	}
	if host.AuthType == "" {
		host.AuthType = "key"
	}
	host.UpdatedAt = crypto.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return Host{}, err
	}
	result, err := tx.Exec(`UPDATE hosts SET name=?,address=?,port=?,username=?,auth_type=?,key_path=?,
		os_family=?,os_version=?,status=?,tags=?,group_name=?,cmdb_ci_id=?,updated_at=? WHERE id=?`,
		host.Name, host.Address, host.Port, host.Username, host.AuthType, host.KeyPath,
		host.OSFamily, host.OSVersion, host.Status, host.Tags, host.GroupName, host.CMDBCIID,
		host.UpdatedAt, host.ID)
	if err != nil {
		_ = tx.Rollback()
		return Host{}, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		_ = tx.Rollback()
		return Host{}, sql.ErrNoRows
	}
	if err := s.addAuditTx(tx, actor, "update", "host", host.ID, host.Name); err != nil {
		_ = tx.Rollback()
		return Host{}, err
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return host, nil
}

// DeleteHost removes a host and its related facts/keys/runs.
func (s *Store) DeleteHost(id string) error {
	return s.DeleteHostAs("local", id)
}

// DeleteHostAs removes a host and records the supplied audit actor.
func (s *Store) DeleteHostAs(actor, id string) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "local"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	result, err := tx.Exec("DELETE FROM hosts WHERE id=?", id)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		_ = tx.Rollback()
		return sql.ErrNoRows
	}
	if err := s.addAuditTx(tx, actor, "delete", "host", id, ""); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ListHosts returns hosts with their latest facts and trusted key.
func (s *Store) ListHosts() ([]Host, error) {
	rows, err := s.db.Query(`SELECT h.id,h.name,h.address,h.port,h.username,h.auth_type,h.key_path,
		h.os_family,h.os_version,h.status,h.tags,h.group_name,h.cmdb_ci_id,h.created_at,h.updated_at,
		f.collected_at,f.uptime_seconds,f.boot_time,f.kernel,f.os_pretty_name,f.package_manager,
		f.reboot_required,f.disk_free_bytes,f.time_sync_ok,f.pending_updates,
		f.agent_version,f.agent_build_number,f.agent_build_commit,f.agent_build_date,
		f.agent_build_target,f.agent_build_type,
		(SELECT COUNT(*) FROM docker_projects dp WHERE dp.host_id=h.id),
		(SELECT COUNT(*) FROM docker_containers dc WHERE dc.host_id=h.id)
		FROM hosts h LEFT JOIN host_facts f ON f.host_id=h.id ORDER BY h.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []Host
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

// FindHostByAddress returns a host by address and port, if present.
func (s *Store) FindHostByAddress(address string, port int) (Host, error) {
	row := s.db.QueryRow(`SELECT h.id,h.name,h.address,h.port,h.username,h.auth_type,h.key_path,
		h.os_family,h.os_version,h.status,h.tags,h.group_name,h.cmdb_ci_id,h.created_at,h.updated_at,
		f.collected_at,f.uptime_seconds,f.boot_time,f.kernel,f.os_pretty_name,f.package_manager,
		f.reboot_required,f.disk_free_bytes,f.time_sync_ok,f.pending_updates,
		f.agent_version,f.agent_build_number,f.agent_build_commit,f.agent_build_date,
		f.agent_build_target,f.agent_build_type,
		(SELECT COUNT(*) FROM docker_projects dp WHERE dp.host_id=h.id),
		(SELECT COUNT(*) FROM docker_containers dc WHERE dc.host_id=h.id)
		FROM hosts h LEFT JOIN host_facts f ON f.host_id=h.id WHERE h.address=? AND h.port=?`, address, port)
	return scanHost(row)
}

// GetHost returns one host by ID.
func (s *Store) GetHost(id string) (Host, error) {
	row := s.db.QueryRow(`SELECT h.id,h.name,h.address,h.port,h.username,h.auth_type,h.key_path,
		h.os_family,h.os_version,h.status,h.tags,h.group_name,h.cmdb_ci_id,h.created_at,h.updated_at,
		f.collected_at,f.uptime_seconds,f.boot_time,f.kernel,f.os_pretty_name,f.package_manager,
		f.reboot_required,f.disk_free_bytes,f.time_sync_ok,f.pending_updates,
		f.agent_version,f.agent_build_number,f.agent_build_commit,f.agent_build_date,
		f.agent_build_target,f.agent_build_type,
		(SELECT COUNT(*) FROM docker_projects dp WHERE dp.host_id=h.id),
		(SELECT COUNT(*) FROM docker_containers dc WHERE dc.host_id=h.id)
		FROM hosts h LEFT JOIN host_facts f ON f.host_id=h.id WHERE h.id=?`, id)
	return scanHost(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanHost(row scanner) (Host, error) {
	var host Host
	var collectedAt, bootTime, kernel, pretty, pkg sql.NullString
	var agentVersion, agentBuildNumber, agentBuildCommit sql.NullString
	var agentBuildDate, agentBuildTarget, agentBuildType sql.NullString
	var uptime, disk, pending sql.NullInt64
	var reboot, timeSync sql.NullBool
	err := row.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.Username, &host.AuthType, &host.KeyPath,
		&host.OSFamily, &host.OSVersion, &host.Status, &host.Tags, &host.GroupName, &host.CMDBCIID, &host.CreatedAt, &host.UpdatedAt,
		&collectedAt, &uptime, &bootTime, &kernel, &pretty, &pkg, &reboot, &disk, &timeSync, &pending,
		&agentVersion, &agentBuildNumber, &agentBuildCommit, &agentBuildDate, &agentBuildTarget, &agentBuildType,
		&host.DockerProjectCount, &host.DockerContainerCount)
	if err != nil {
		return Host{}, err
	}
	if collectedAt.Valid {
		host.Facts = &Facts{
			CollectedAt:    collectedAt.String,
			UptimeSeconds:  uptime.Int64,
			BootTime:       bootTime.String,
			Kernel:         kernel.String,
			OSPrettyName:   pretty.String,
			PackageManager: pkg.String,
			RebootRequired: reboot.Bool,
			DiskFreeBytes:  disk.Int64,
			TimeSyncOK:     timeSync.Bool,
			PendingUpdates: int(pending.Int64),
			Agent: buildinfo.Info{
				Version:     agentVersion.String,
				BuildNumber: agentBuildNumber.String,
				BuildCommit: agentBuildCommit.String,
				BuildDate:   agentBuildDate.String,
				BuildTarget: agentBuildTarget.String,
				BuildType:   agentBuildType.String,
			},
		}
	}
	return host, nil
}

// SaveHostKey trusts a host key.
func (s *Store) SaveHostKey(key HostKey) error {
	return s.SaveHostKeyAs("local", key)
}

// SaveHostKeyAs trusts a host key and records the supplied actor.
func (s *Store) SaveHostKeyAs(actor string, key HostKey) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "local"
	}
	now := crypto.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO host_keys(host_id,key_type,fingerprint,first_seen,last_seen,trusted)
		VALUES(?,?,?,?,?,1)
		ON CONFLICT(host_id,key_type,fingerprint) DO UPDATE SET last_seen=excluded.last_seen,trusted=1`,
		key.HostID, key.KeyType, key.Fingerprint, now, now)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := s.addAuditTx(tx, actor, "trust-key", "host", key.HostID, key.KeyType+" "+key.Fingerprint); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// GetHostKey returns the trusted key for a host, if any.
func (s *Store) GetHostKey(hostID string) (*HostKey, error) {
	var key HostKey
	err := s.db.QueryRow(`SELECT host_id,key_type,fingerprint,first_seen,last_seen FROM host_keys
		WHERE host_id=? AND trusted=1 ORDER BY last_seen DESC LIMIT 1`, hostID).
		Scan(&key.HostID, &key.KeyType, &key.Fingerprint, &key.FirstSeen, &key.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// SaveFacts stores the latest facts and audits the collection.
func (s *Store) SaveFacts(hostID string, facts Facts) error {
	return s.SaveFactsAs("local", hostID, facts)
}

// SaveFactsAs stores the latest facts and records the supplied audit actor.
func (s *Store) SaveFactsAs(actor, hostID string, facts Facts) error {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "local"
	}
	if facts.CollectedAt == "" {
		facts.CollectedAt = crypto.Now()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO host_facts
		(host_id,collected_at,uptime_seconds,boot_time,kernel,os_pretty_name,package_manager,reboot_required,disk_free_bytes,time_sync_ok,pending_updates,
			agent_version,agent_build_number,agent_build_commit,agent_build_date,agent_build_target,agent_build_type)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(host_id) DO UPDATE SET
			collected_at=excluded.collected_at, uptime_seconds=excluded.uptime_seconds,
			boot_time=excluded.boot_time, kernel=excluded.kernel, os_pretty_name=excluded.os_pretty_name,
			package_manager=excluded.package_manager, reboot_required=excluded.reboot_required,
			disk_free_bytes=excluded.disk_free_bytes, time_sync_ok=excluded.time_sync_ok,
			pending_updates=excluded.pending_updates, agent_version=excluded.agent_version,
			agent_build_number=excluded.agent_build_number, agent_build_commit=excluded.agent_build_commit,
			agent_build_date=excluded.agent_build_date, agent_build_target=excluded.agent_build_target,
			agent_build_type=excluded.agent_build_type`,
		hostID, facts.CollectedAt, facts.UptimeSeconds, facts.BootTime, facts.Kernel, facts.OSPrettyName,
		facts.PackageManager, facts.RebootRequired, facts.DiskFreeBytes, facts.TimeSyncOK, facts.PendingUpdates,
		facts.Agent.Version, facts.Agent.BuildNumber, facts.Agent.BuildCommit, facts.Agent.BuildDate,
		facts.Agent.BuildTarget, facts.Agent.BuildType)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec("UPDATE hosts SET status='reachable', updated_at=? WHERE id=?", crypto.Now(), hostID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := s.addAuditTx(tx, actor, "facts", "host", hostID, fmt.Sprintf("%d pending updates", facts.PendingUpdates)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SetHostStatus updates the connection status.
func (s *Store) SetHostStatus(hostID, status string) error {
	_, err := s.db.Exec("UPDATE hosts SET status=?, updated_at=? WHERE id=?", status, crypto.Now(), hostID)
	return err
}

// AddAudit appends one audit entry.
func (s *Store) AddAudit(actor, action, entityType, entityID, detail string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := s.addAuditTx(tx, actor, action, entityType, entityID, detail); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) addAuditTx(tx *sql.Tx, actor, action, entityType, entityID, detail string) error {
	prev := strings.Repeat("0", 64)
	err := tx.QueryRow("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	ts := crypto.Now()
	hash := auditHash(prev, ts, actor, action, entityType, entityID, detail)
	_, err = tx.Exec(`INSERT INTO audit_log(ts,actor,action,entity_type,entity_id,detail,prev_hash,hash)
		VALUES(?,?,?,?,?,?,?,?)`, ts, actor, action, entityType, entityID, detail, prev, hash)
	return err
}

func auditHash(prev, ts, actor, action, entityType, entityID, detail string) string {
	payload := strings.Join([]string{prev, ts, actor, action, entityType, entityID, detail}, "\x1f")
	sum := blake2b.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ListAudit returns the newest audit entries first.
func (s *Store) ListAudit(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id,ts,actor,action,entity_type,entity_id,detail,prev_hash,hash
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.TS, &entry.Actor, &entry.Action, &entry.EntityType,
			&entry.EntityID, &entry.Detail, &entry.PrevHash, &entry.Hash); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// VerifyAudit recomputes the entire audit chain.
func (s *Store) VerifyAudit() error {
	return verifyAuditDB(s.db)
}

func verifyAuditDB(db *sql.DB) error {
	rows, err := db.Query("SELECT id,ts,actor,action,entity_type,entity_id,detail,prev_hash,hash FROM audit_log ORDER BY id")
	if err != nil {
		return err
	}
	defer rows.Close()
	prev := strings.Repeat("0", 64)
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.TS, &entry.Actor, &entry.Action, &entry.EntityType,
			&entry.EntityID, &entry.Detail, &entry.PrevHash, &entry.Hash); err != nil {
			return err
		}
		if entry.PrevHash != prev {
			return fmt.Errorf("audit chain broken at row %d: prev_hash mismatch", entry.ID)
		}
		if auditHash(entry.PrevHash, entry.TS, entry.Actor, entry.Action, entry.EntityType, entry.EntityID, entry.Detail) != entry.Hash {
			return fmt.Errorf("audit chain broken at row %d: hash mismatch", entry.ID)
		}
		prev = entry.Hash
	}
	return rows.Err()
}

// CountHosts returns the number of managed hosts.
func (s *Store) CountHosts() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&count)
	return count, err
}

// CountAudit returns the number of audit entries.
func (s *Store) CountAudit() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&count)
	return count, err
}

// Backup creates a consistent encrypted copy plus sidecar at dest.
func (s *Store) Backup(dest string) error {
	if strings.TrimSpace(dest) == "" {
		return errors.New("backup path is required")
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if abs == s.path {
		return errors.New("backup path must differ from the database path")
	}
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("backup already exists: %s", abs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(crypto.SidecarPath(abs)); err == nil {
		return fmt.Errorf("backup sidecar already exists: %s", crypto.SidecarPath(abs))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return err
	}

	if err := backupDatabase(abs, s.db); err != nil {
		_ = os.Remove(abs)
		return err
	}
	if err := copyFile(crypto.SidecarPath(s.path), crypto.SidecarPath(abs)); err != nil {
		_ = os.Remove(abs)
		return err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return err
	}
	if err := verifyBackup(abs, s.key); err != nil {
		_ = os.Remove(abs)
		_ = os.Remove(crypto.SidecarPath(abs))
		return err
	}
	_, retention := s.BackupConfig()
	if err := pruneManagedBackups(filepath.Dir(abs), retention); err != nil {
		slog.Warn("backup retention", "directory", filepath.Dir(abs), "error", err)
	}
	return nil
}

// Restore copies a backup pair to a new database path and verifies it with the
// current key. The destination must not exist.
func (s *Store) Restore(backupPath, destPath string) error {
	if strings.TrimSpace(backupPath) == "" || strings.TrimSpace(destPath) == "" {
		return errors.New("backup and destination paths are required")
	}
	src, err := filepath.Abs(backupPath)
	if err != nil {
		return err
	}
	dst, err := filepath.Abs(destPath)
	if err != nil {
		return err
	}
	if src == dst {
		return errors.New("backup and destination must differ")
	}
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup database: %w", err)
	}
	if _, err := os.Stat(crypto.SidecarPath(src)); err != nil {
		return fmt.Errorf("backup sidecar: %w", err)
	}
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("destination already exists: %s", dst)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(crypto.SidecarPath(dst)); err == nil {
		return fmt.Errorf("destination sidecar already exists: %s", crypto.SidecarPath(dst))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	if err := copyFile(crypto.SidecarPath(src), crypto.SidecarPath(dst)); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return err
	}
	if err := verifyBackup(dst, s.key); err != nil {
		_ = os.Remove(dst)
		_ = os.Remove(crypto.SidecarPath(dst))
		return err
	}
	return nil
}

func backupDatabase(dest string, src *sql.DB) error {
	escaped := strings.ReplaceAll(dest, "'", "''")
	attach := fmt.Sprintf(`ATTACH DATABASE '%s' AS hibp_backup`, escaped)
	if _, err := src.Exec(attach); err != nil {
		return fmt.Errorf("attach backup: %w", err)
	}
	defer func() { _, _ = src.Exec("DETACH DATABASE hibp_backup") }()
	if _, err := src.Exec("SELECT sqlcipher_export('hibp_backup')"); err != nil {
		return fmt.Errorf("export backup: %w", err)
	}
	return nil
}

func verifyBackup(path string, key []byte) error {
	db, err := openSQLCipher(path, key)
	if err != nil {
		return err
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		return fmt.Errorf("backup verification failed: %w", err)
	}
	if count == 0 {
		return errors.New("backup verification failed: no migrations")
	}
	if err := verifyAuditDB(db); err != nil {
		return fmt.Errorf("backup verification failed: audit chain: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// TimeNow is exposed for tests that need deterministic formatting.
func TimeNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }
