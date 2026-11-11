-- Per-host retry count for scheduled patch attempts.
ALTER TABLE schedules ADD COLUMN retries INTEGER NOT NULL DEFAULT 0;
