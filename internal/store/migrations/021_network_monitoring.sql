-- SNMP polling state and latest values for network-device hosts.
CREATE TABLE IF NOT EXISTS snmp_values (
    host_id TEXT NOT NULL,
    oid TEXT NOT NULL,
    value TEXT NOT NULL,
    value_type TEXT NOT NULL DEFAULT 'string',
    collected_at TEXT NOT NULL,
    PRIMARY KEY (host_id, oid),
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_snmp_values_host ON snmp_values(host_id);

CREATE TABLE IF NOT EXISTS snmp_poll_state (
    host_id TEXT PRIMARY KEY,
    last_poll TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
