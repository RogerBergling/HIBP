-- Last Docker Compose check result per host/project. The cached inventory is
-- refreshed independently; these rows preserve update status across reloads.
CREATE TABLE IF NOT EXISTS docker_project_checks (
    host_id TEXT NOT NULL,
    project TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    checked_at TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, project),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
