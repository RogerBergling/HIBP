-- The external vCenter/HAProxy/OPNsense integrations were removed. Keep the
-- historical migration files so existing databases continue to validate their
-- checksums, then drop the feature's data here.
DROP TABLE IF EXISTS integration_state;
DROP TABLE IF EXISTS integration_events;
DELETE FROM settings WHERE scope LIKE 'integration:%';
