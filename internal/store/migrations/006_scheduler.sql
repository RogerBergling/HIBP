-- Patch schedules and per-host run history. The existing runs table is reused
-- for scheduler evidence; schedule_id links each run to its definition.
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'check',
    enabled INTEGER NOT NULL DEFAULT 1,
    cron TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    window_minutes INTEGER NOT NULL DEFAULT 120,
    jitter_seconds INTEGER NOT NULL DEFAULT 60,
    max_concurrency INTEGER NOT NULL DEFAULT 3,
    run_if_missed INTEGER NOT NULL DEFAULT 0,
    notify TEXT NOT NULL DEFAULT 'failures',
    recipients TEXT NOT NULL DEFAULT '',
    last_run_at TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT '',
    last_summary TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedule_assignments (
    schedule_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (schedule_id, scope, target),
    FOREIGN KEY (schedule_id) REFERENCES schedules(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_schedule_assignments_target ON schedule_assignments(scope, target);

ALTER TABLE runs ADD COLUMN schedule_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_runs_schedule ON runs(schedule_id, started_at);
CREATE INDEX IF NOT EXISTS idx_runs_host_time ON runs(host_id, started_at);
