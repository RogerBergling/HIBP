-- Hostapd RADIUS accounting start/stop messages are WiFi client activity, not
-- authentication failures. Correct historical false positives from the old
-- broad "radius" match.
UPDATE host_events
SET category = 'network_wifi',
    severity = 'info'
WHERE category = 'auth_failure'
  AND (
      message LIKE '%RADIUS: starting accounting%'
      OR message LIKE '%RADIUS: stopping accounting%'
  );
