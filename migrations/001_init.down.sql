-- Reverse 001_init: drop seed-dependent objects and schema in reverse order.

DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS request_logs CASCADE;
DROP FUNCTION IF EXISTS ensure_request_logs_partition(TIMESTAMPTZ);
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS policies CASCADE;
DROP TABLE IF EXISTS reusable_objects CASCADE;
DROP TABLE IF EXISTS block_pages CASCADE;
DROP TABLE IF EXISTS settings CASCADE;
DROP TABLE IF EXISTS certificates CASCADE;
DROP TABLE IF EXISTS proxy_auth_cache CASCADE;
DROP TABLE IF EXISTS admin_sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- pgcrypto may be shared; leave extension in place.
