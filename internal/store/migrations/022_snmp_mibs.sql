-- Imported MIB library and resolved symbol index for SNMP names and labels.
CREATE TABLE IF NOT EXISTS snmp_mibs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL,
    modules TEXT NOT NULL DEFAULT '',
    symbol_count INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snmp_mib_symbols (
    oid TEXT NOT NULL,
    name TEXT NOT NULL,
    module TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    syntax TEXT NOT NULL DEFAULT '',
    units TEXT NOT NULL DEFAULT '',
    enums TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (name, module)
);

CREATE INDEX IF NOT EXISTS idx_snmp_mib_symbols_oid ON snmp_mib_symbols(oid);
CREATE INDEX IF NOT EXISTS idx_snmp_mib_symbols_name ON snmp_mib_symbols(name);
