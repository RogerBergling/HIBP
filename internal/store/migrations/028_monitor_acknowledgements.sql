-- Per-host acknowledgements for current monitor alerts. Acknowledgement never
-- changes a critical state; it suppresses repeat notifications until recovery
-- or severity escalation.
ALTER TABLE monitor_state ADD COLUMN acknowledged_at TEXT NOT NULL DEFAULT '';
ALTER TABLE monitor_state ADD COLUMN acknowledged_by TEXT NOT NULL DEFAULT '';
ALTER TABLE monitor_state ADD COLUMN acknowledgement_note TEXT NOT NULL DEFAULT '';
ALTER TABLE monitor_state ADD COLUMN acknowledged_status TEXT NOT NULL DEFAULT '';
