-- Monitoring definitions are intentionally separate from hosts so a monitor
-- can be assigned to the fleet, a group, a tag, or one host.
CREATE TABLE IF NOT EXISTS monitors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    warning REAL NOT NULL DEFAULT 0,
    critical REAL NOT NULL DEFAULT 0,
    interval_seconds INTEGER NOT NULL DEFAULT 300,
    repeat_minutes INTEGER NOT NULL DEFAULT 60,
    cooldown_minutes INTEGER NOT NULL DEFAULT 15,
    recipients TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_checked_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_assignments (
    monitor_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (monitor_id, scope, target),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitor_assignments_target ON monitor_assignments(scope, target);

CREATE TABLE IF NOT EXISTS monitor_state (
    monitor_id TEXT NOT NULL,
    host_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    message TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    last_notified TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (monitor_id, host_id),
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alert_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL,
    host_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    emailed INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_events_time ON alert_events(created_at);

-- Snapshot of systemd units from the lightweight metrics collection. The
-- monitor engine uses this to evaluate service up/down checks without opening a
-- new SSH connection for every service monitor.
CREATE TABLE IF NOT EXISTS host_services (
    host_id TEXT NOT NULL,
    unit TEXT NOT NULL,
    state TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, unit),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_host_services_host ON host_services(host_id);
