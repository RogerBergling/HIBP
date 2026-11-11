-- Read-only observability snapshots. Docker and system data are cached locally so
-- the UI can render quickly without opening a new SSH session per page view.
CREATE TABLE IF NOT EXISTS host_system_info (
    host_id TEXT PRIMARY KEY,
    collected_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS host_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    cpu_percent REAL NOT NULL DEFAULT 0,
    memory_percent REAL NOT NULL DEFAULT 0,
    swap_percent REAL NOT NULL DEFAULT 0,
    disk_percent REAL NOT NULL DEFAULT 0,
    load1 REAL NOT NULL DEFAULT 0,
    load5 REAL NOT NULL DEFAULT 0,
    load15 REAL NOT NULL DEFAULT 0,
    uptime_seconds INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_host_metrics_host_time ON host_metrics(host_id, collected_at);

CREATE TABLE IF NOT EXISTS docker_projects (
    host_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT '',
    config_files TEXT NOT NULL DEFAULT '',
    working_dir TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, name),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS docker_containers (
    host_id TEXT NOT NULL,
    container_id TEXT NOT NULL,
    name TEXT NOT NULL,
    project TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    image TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    health TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, container_id),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_docker_containers_host ON docker_containers(host_id, project);

-- Fleet defaults live under scope='fleet'. A host override lives under
-- scope='host:<uuid>'. The server resolves host -> fleet -> built-in default.
CREATE TABLE IF NOT EXISTS settings (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);
