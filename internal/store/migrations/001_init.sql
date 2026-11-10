CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL,
    auth_type TEXT NOT NULL DEFAULT 'key',
    key_path TEXT NOT NULL DEFAULT '',
    os_family TEXT NOT NULL DEFAULT '',
    os_version TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    tags TEXT NOT NULL DEFAULT '',
    group_name TEXT NOT NULL DEFAULT '',
    cmdb_ci_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(address, port)
);

CREATE INDEX IF NOT EXISTS idx_hosts_name ON hosts(name);
CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(address);
CREATE INDEX IF NOT EXISTS idx_hosts_group ON hosts(group_name);

CREATE TABLE IF NOT EXISTS host_keys (
    host_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, key_type, fingerprint),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_facts (
    host_id TEXT PRIMARY KEY,
    collected_at TEXT NOT NULL,
    uptime_seconds INTEGER NOT NULL DEFAULT 0,
    boot_time TEXT NOT NULL DEFAULT '',
    kernel TEXT NOT NULL DEFAULT '',
    os_pretty_name TEXT NOT NULL DEFAULT '',
    package_manager TEXT NOT NULL DEFAULT '',
    reboot_required INTEGER NOT NULL DEFAULT 0,
    disk_free_bytes INTEGER NOT NULL DEFAULT 0,
    time_sync_ok INTEGER NOT NULL DEFAULT 0,
    pending_updates INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    exit_code INTEGER NOT NULL DEFAULT 0,
    output TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_host ON runs(host_id, started_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
