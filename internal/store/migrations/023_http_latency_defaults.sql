-- Raise low active HTTP/HTTPS latency thresholds to the new 400 ms warning and
-- 500 ms critical defaults. Disabled thresholds (0) stay disabled, and higher
-- existing thresholds are preserved.
UPDATE monitors
SET warning = CASE
        WHEN warning > 0 AND warning < 400 THEN 400
        ELSE warning
    END,
    critical = CASE
        WHEN critical > 0 AND critical < 500 THEN 500
        ELSE critical
    END,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE type = 'http'
  AND (
      (warning > 0 AND warning < 400)
      OR (critical > 0 AND critical < 500)
  );
