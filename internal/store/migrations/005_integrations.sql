-- External integration state and history. Configuration uses the existing
-- settings table scopes (integration:vcenter, integration:haproxy,
-- integration:opnsense); secrets remain encrypted with the database.
CREATE TABLE IF NOT EXISTS integration_state (
    source TEXT NOT NULL,
    event_key TEXT NOT NULL,
    status TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_notified TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source, event_key)
);

CREATE TABLE IF NOT EXISTS integration_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_key TEXT NOT NULL,
    status TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    emailed INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_integration_events_time ON integration_events(created_at);
CREATE INDEX IF NOT EXISTS idx_integration_events_source ON integration_events(source, created_at);
