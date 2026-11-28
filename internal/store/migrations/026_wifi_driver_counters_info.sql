-- MediaTek/Ralink mc2uc driver counters are periodic WiFi diagnostics, not
-- warnings. Normalize existing rows from AP kernel logs.
UPDATE host_events
SET category = 'network_wifi',
    severity = 'info'
WHERE (category <> 'network_wifi' OR severity <> 'info')
  AND (
      message LIKE '%mc2uc%'
      OR message LIKE '%sta_cnt[%'
  );
