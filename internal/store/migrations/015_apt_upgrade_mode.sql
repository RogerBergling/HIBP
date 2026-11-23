-- Per-host APT transaction policy. safe keeps the historical `apt-get upgrade`
-- behavior; full uses `apt-get full-upgrade` and may install or remove packages.
ALTER TABLE hosts ADD COLUMN apt_upgrade_mode TEXT NOT NULL DEFAULT 'safe';
