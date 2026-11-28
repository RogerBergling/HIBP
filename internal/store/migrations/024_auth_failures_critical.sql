-- Authentication failures are critical events. Normalize existing normalized
-- event history so dashboards and filters agree with the new classification.
UPDATE host_events
SET severity = 'critical'
WHERE category = 'auth_failure'
  AND severity <> 'critical';
