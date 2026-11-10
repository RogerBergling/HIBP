-- Authentication is deliberately single-user in v1. The schema leaves room for
-- multiple users later, but the setup endpoint refuses to create more than one.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_pending_secret TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- The full WebAuthn credential is stored as JSON so sign-counter and flag
-- updates can be written back exactly as the library expects. The database is
-- SQLCipher-encrypted at rest.
CREATE TABLE IF NOT EXISTS user_passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    credential_json TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_passkeys_user ON user_passkeys(user_id);

-- Only a SHA-256 hash of the session token is stored. A database leak does not
-- yield a directly usable cookie. Pending MFA sessions are short-lived and are
-- replaced by a fresh token after MFA succeeds.
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    mfa_verified INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
