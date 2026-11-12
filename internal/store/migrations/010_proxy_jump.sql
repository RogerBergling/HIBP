-- Optional single-hop SSH jump host. Empty address means a direct connection.
-- The jump host has its own trusted key so it is never confused with the
-- managed target's host key.
ALTER TABLE hosts ADD COLUMN proxy_jump_address TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN proxy_jump_port INTEGER NOT NULL DEFAULT 22;
ALTER TABLE hosts ADD COLUMN proxy_jump_username TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN proxy_jump_key_path TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN proxy_jump_key_type TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN proxy_jump_key_fingerprint TEXT NOT NULL DEFAULT '';
