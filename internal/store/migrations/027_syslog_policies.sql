-- Safe syslog policy engine. Policies may classify or suppress events, but
-- suppressed events are retained. Critical events and protected kernel
-- failures are guarded in code and cannot be suppressed or downgraded.
CREATE TABLE IF NOT EXISTS syslog_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'fleet',
    host_id TEXT,
    match_type TEXT NOT NULL DEFAULT 'contains',
    pattern TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    suppress INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_syslog_policies_enabled
    ON syslog_policies(enabled, scope, priority);
CREATE INDEX IF NOT EXISTS idx_syslog_policies_host
    ON syslog_policies(host_id);

ALTER TABLE host_events ADD COLUMN original_category TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN original_severity TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN policy_id TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN policy_name TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_events ADD COLUMN guardrail INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_host_events_suppressed
    ON host_events(suppressed, occurred_at);
CREATE INDEX IF NOT EXISTS idx_host_events_policy
    ON host_events(policy_id);
