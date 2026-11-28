-- Security event triage acknowledgement. This marks an event as reviewed but
-- never changes its severity, retention, monitor counts, or guardrails.
ALTER TABLE host_events ADD COLUMN acknowledged_at TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN acknowledged_by TEXT NOT NULL DEFAULT '';
ALTER TABLE host_events ADD COLUMN acknowledgement_note TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_host_events_acknowledged
    ON host_events(acknowledged_at);
