-- NTP/clock telemetry and the fleet-wide NTP default monitor.
ALTER TABLE host_facts ADD COLUMN time_sync_source TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN time_sync_offset_seconds REAL NOT NULL DEFAULT 0;
ALTER TABLE host_facts ADD COLUMN time_sync_stratum INTEGER NOT NULL DEFAULT 0;
ALTER TABLE host_facts ADD COLUMN time_sync_last_sync TEXT NOT NULL DEFAULT '';
ALTER TABLE host_facts ADD COLUMN time_sync_offset_known INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO monitors(id,name,type,target,warning,critical,interval_seconds,
    repeat_minutes,cooldown_minutes,recipients,enabled,last_checked_at,created_at,updated_at)
VALUES
    ('default-ntp-clock','NTP clock','host.ntp','',1,5,300,60,15,'',1,'',
        strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'));

INSERT OR IGNORE INTO monitor_assignments(monitor_id,scope,target)
VALUES ('default-ntp-clock','fleet','');
