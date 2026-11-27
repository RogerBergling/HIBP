-- Cross-platform monitoring agents. One agent is bound to one host record.
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
