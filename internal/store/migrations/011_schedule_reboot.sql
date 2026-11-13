-- Optional automatic reboot after a successful scheduled apply when the target
-- reports that a reboot is required. Existing schedules keep the old behavior.
ALTER TABLE schedules ADD COLUMN reboot_after_apply INTEGER NOT NULL DEFAULT 0;
