-- Normalized target events collected from journald/auth logs and, later, the
-- HIBP agent. Raw log lines are not persisted by default.
CREATE TABLE IF NOT EXISTS host_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    source TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    remote_ip TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE(host_id, event_id),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_host_events_host_time ON host_events(host_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_host_events_category_time ON host_events(category, occurred_at);

INSERT OR IGNORE INTO monitors(id,name,type,target,warning,critical,interval_seconds,
    repeat_minutes,cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at)
VALUES
    ('default-security-auth','Failed authentication','security.auth','',5,10,300,60,15,'',1,'',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO monitor_assignments(monitor_id,scope,target)
VALUES ('default-security-auth','fleet','');
