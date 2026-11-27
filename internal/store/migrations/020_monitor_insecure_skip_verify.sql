-- Per-monitor opt-in for self-signed or name-mismatched HTTP endpoints.
ALTER TABLE monitors ADD COLUMN insecure_skip_verify INTEGER NOT NULL DEFAULT 0;
