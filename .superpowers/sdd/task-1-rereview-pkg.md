diff --git a/deploy/docker-compose.yml b/deploy/docker-compose.yml
index ae7a87e..fbffaca 100644
--- a/deploy/docker-compose.yml
+++ b/deploy/docker-compose.yml
@@ -33,15 +33,16 @@ services:
       - "3000:3000"
     volumes:
       - /var/run/docker.sock:/var/run/docker.sock
       - wsp_data:/var/lib/wsp
     depends_on:
       postgres:
         condition: service_healthy
       clamav:
         condition: service_started
     # clamav may take a long time to load signatures ΓÇö wsp must retry clamd
-    restart: unless-stopped
+    # No restart: unless-stopped on wsp ΓÇö avoids thrash if clamd is slow to ready
+    restart: "no"
 
 volumes:
   pgdata:
   wsp_data:
diff --git a/migrations/001_init.up.sql b/migrations/001_init.up.sql
index 9e612e5..4c52031 100644
--- a/migrations/001_init.up.sql
+++ b/migrations/001_init.up.sql
@@ -171,38 +171,41 @@ CREATE TABLE request_logs (
 -- Ensure a monthly partition exists for the month containing target (default: now).
 CREATE OR REPLACE FUNCTION ensure_request_logs_partition(target TIMESTAMPTZ DEFAULT now())
 RETURNS TEXT
 LANGUAGE plpgsql
 AS $$
 DECLARE
     start_ts  TIMESTAMPTZ;
     end_ts    TIMESTAMPTZ;
     part_name TEXT;
 BEGIN
-    start_ts := date_trunc('month', target AT TIME ZONE 'UTC');
+    -- date_trunc(... AT TIME ZONE 'UTC') yields timestamp without tz (UTC wall clock);
+    -- re-apply AT TIME ZONE 'UTC' so bounds are true UTC TIMESTAMPTZ, not session-local.
+    start_ts := (date_trunc('month', target AT TIME ZONE 'UTC')) AT TIME ZONE 'UTC';
     end_ts := start_ts + INTERVAL '1 month';
-    part_name := 'request_logs_' || to_char(start_ts, 'YYYY_MM');
+    part_name := 'request_logs_' || to_char(start_ts AT TIME ZONE 'UTC', 'YYYY_MM');
 
     EXECUTE format(
         'CREATE TABLE IF NOT EXISTS %I PARTITION OF request_logs FOR VALUES FROM (%L) TO (%L)',
         part_name,
         start_ts,
         end_ts
     );
 
     RETURN part_name;
 END;
 $$;
 
 -- Seed partitions for current and next UTC month so inserts work immediately.
-SELECT ensure_request_logs_partition(now() AT TIME ZONE 'UTC');
-SELECT ensure_request_logs_partition((now() AT TIME ZONE 'UTC') + INTERVAL '1 month');
+-- Pass TIMESTAMPTZ (now()); do not use now() AT TIME ZONE 'UTC' (timestamp without time zone).
+SELECT ensure_request_logs_partition(now());
+SELECT ensure_request_logs_partition(now() + INTERVAL '1 month');
 
 CREATE INDEX request_logs_ts_idx ON request_logs (ts DESC);
 CREATE INDEX request_logs_client_ip_ts_idx ON request_logs (client_ip, ts DESC);
 CREATE INDEX request_logs_username_ts_idx ON request_logs (username, ts DESC);
 CREATE INDEX request_logs_host_ts_idx ON request_logs (host, ts DESC);
 CREATE INDEX request_logs_decision_ts_idx ON request_logs (decision, ts DESC);
 CREATE INDEX request_logs_session_id_ts_idx ON request_logs (session_id, ts DESC);
 CREATE INDEX request_logs_request_id_idx ON request_logs (request_id);
 
 -- ---------------------------------------------------------------------------
