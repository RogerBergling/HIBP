-- Enterprise monitoring baseline. The first successful service snapshot for a
-- host becomes the baseline of units expected to keep running. Later snapshots
-- are compared against it instead of creating one monitor per service.
CREATE TABLE IF NOT EXISTS host_service_baseline (
    host_id TEXT NOT NULL,
    unit TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'running',
    expected INTEGER NOT NULL DEFAULT 1,
    excluded INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, unit),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_host_service_baseline_host ON host_service_baseline(host_id);

-- Fleet-wide default monitors. They are normal editable monitors: operators
-- can disable, retarget, or delete them after reviewing the baseline.
INSERT OR IGNORE INTO monitors(id,name,type,target,warning,critical,interval_seconds,
    repeat_minutes,cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at)
VALUES
    ('default-service-baseline','Service baseline','service.baseline','',0,0,300,60,15,'',1,'',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    ('default-docker-health','Docker health','docker.health','',0,0,300,60,15,'',1,'',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO monitor_assignments(monitor_id,scope,target)
VALUES ('default-service-baseline','fleet',''),
       ('default-docker-health','fleet','');
