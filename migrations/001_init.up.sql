-- WSP v1 initial schema
-- UUID PKs via pgcrypto; request_logs partitioned by month.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- admin_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE admin_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX admin_sessions_token_hash_idx ON admin_sessions (token_hash);
CREATE INDEX admin_sessions_user_id_idx ON admin_sessions (user_id);
CREATE INDEX admin_sessions_expires_at_idx ON admin_sessions (expires_at);

-- ---------------------------------------------------------------------------
-- proxy_auth_cache (IP-cached proxy authentication)
-- ---------------------------------------------------------------------------
CREATE TABLE proxy_auth_cache (
    ip         TEXT PRIMARY KEY,
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX proxy_auth_cache_expires_at_idx ON proxy_auth_cache (expires_at);

-- ---------------------------------------------------------------------------
-- certificates
-- ---------------------------------------------------------------------------
CREATE TABLE certificates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT NOT NULL,
    kind               TEXT NOT NULL CHECK (kind IN ('self_signed_ca')),
    cert_pem           TEXT NOT NULL,
    key_pem_encrypted  BYTEA NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    not_before         TIMESTAMPTZ NOT NULL,
    not_after          TIMESTAMPTZ NOT NULL,
    is_active          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX certificates_one_active_ca_idx
    ON certificates (is_active)
    WHERE is_active = TRUE AND kind = 'self_signed_ca';

-- ---------------------------------------------------------------------------
-- settings (key / JSONB value)
-- ---------------------------------------------------------------------------
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- block_pages
-- ---------------------------------------------------------------------------
CREATE TABLE block_pages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    html       TEXT NOT NULL,
    is_system  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- reusable_objects
-- ---------------------------------------------------------------------------
CREATE TABLE reusable_objects (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_system  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX reusable_objects_type_idx ON reusable_objects (type);

-- ---------------------------------------------------------------------------
-- policies (ordered rules; lower priority = evaluated first)
-- ---------------------------------------------------------------------------
CREATE TABLE policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL,
    sections    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX policies_priority_idx ON policies (priority);
CREATE INDEX policies_enabled_idx ON policies (enabled);

-- ---------------------------------------------------------------------------
-- sessions (browsing sessions grouping related requests)
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at   TIMESTAMPTZ,
    client_ip  TEXT,
    username   TEXT,
    user_agent TEXT,
    summary    JSONB
);

CREATE INDEX sessions_started_at_idx ON sessions (started_at DESC);
CREATE INDEX sessions_client_ip_idx ON sessions (client_ip, started_at DESC);
CREATE INDEX sessions_username_idx ON sessions (username, started_at DESC);

-- ---------------------------------------------------------------------------
-- request_logs (RANGE-partitioned by month on ts)
-- ---------------------------------------------------------------------------
CREATE TABLE request_logs (
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    session_id         UUID,
    request_id         UUID NOT NULL,
    ts                 TIMESTAMPTZ NOT NULL,
    client_ip          TEXT,
    username           TEXT,
    user_agent         TEXT,
    method             TEXT,
    scheme             TEXT,
    host               TEXT,
    path               TEXT,
    query              TEXT,
    url                TEXT,
    protocol           TEXT,
    request_size       BIGINT,
    response_size      BIGINT,
    decision           TEXT,
    matched_rule_ids   UUID[] NOT NULL DEFAULT '{}',
    evaluated_rule_ids UUID[] NOT NULL DEFAULT '{}',
    actions            JSONB NOT NULL DEFAULT '{}'::jsonb,
    timings            JSONB NOT NULL DEFAULT '{}'::jsonb,
    block_reason       TEXT,
    block_page_id      UUID,
    error              TEXT,
    PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

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
    -- date_trunc(... AT TIME ZONE 'UTC') yields timestamp without tz (UTC wall clock);
    -- re-apply AT TIME ZONE 'UTC' so bounds are true UTC TIMESTAMPTZ, not session-local.
    start_ts := (date_trunc('month', target AT TIME ZONE 'UTC')) AT TIME ZONE 'UTC';
    end_ts := start_ts + INTERVAL '1 month';
    part_name := 'request_logs_' || to_char(start_ts AT TIME ZONE 'UTC', 'YYYY_MM');

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
-- Pass TIMESTAMPTZ (now()); do not use now() AT TIME ZONE 'UTC' (timestamp without time zone).
SELECT ensure_request_logs_partition(now());
SELECT ensure_request_logs_partition(now() + INTERVAL '1 month');

CREATE INDEX request_logs_ts_idx ON request_logs (ts DESC);
CREATE INDEX request_logs_client_ip_ts_idx ON request_logs (client_ip, ts DESC);
CREATE INDEX request_logs_username_ts_idx ON request_logs (username, ts DESC);
CREATE INDEX request_logs_host_ts_idx ON request_logs (host, ts DESC);
CREATE INDEX request_logs_decision_ts_idx ON request_logs (decision, ts DESC);
CREATE INDEX request_logs_session_id_ts_idx ON request_logs (session_id, ts DESC);
CREATE INDEX request_logs_request_id_idx ON request_logs (request_id);

-- ---------------------------------------------------------------------------
-- audit_logs
-- ---------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id  UUID,
    actor_username TEXT,
    action         TEXT NOT NULL,
    target_type    TEXT,
    target_id      TEXT,
    summary        TEXT,
    detail         JSONB,
    ip             TEXT
);

CREATE INDEX audit_logs_ts_idx ON audit_logs (ts DESC);
CREATE INDEX audit_logs_actor_ts_idx ON audit_logs (actor_user_id, ts DESC);
CREATE INDEX audit_logs_action_ts_idx ON audit_logs (action, ts DESC);

-- ===========================================================================
-- Seed data
-- ===========================================================================

-- Settings: setup incomplete until wizard creates admin; retention defaults.
INSERT INTO settings (key, value) VALUES
    ('setup_completed', 'false'::jsonb),
    ('log_retention_days', '30'::jsonb),
    ('audit_retention_days', '365'::jsonb),
    ('dns_servers', '["1.1.1.1", "8.8.8.8"]'::jsonb),
    ('proxy_listen', '":8080"'::jsonb),
    ('admin_listen', '":3000"'::jsonb),
    ('platform', '{"product":"wsp","version":"0.1.0"}'::jsonb);

-- System default block page
INSERT INTO block_pages (id, name, html, is_system) VALUES (
    '00000000-0000-4000-8000-000000000001',
    'Default Block Page',
    $html$<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Access Blocked</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
           display: grid; place-items: center; min-height: 100vh; margin: 0; }
    main { max-width: 32rem; padding: 2rem; border: 1px solid #334155; border-radius: 0.75rem;
           background: #1e293b; text-align: center; }
    h1 { margin: 0 0 0.75rem; font-size: 1.5rem; }
    p { margin: 0; color: #94a3b8; line-height: 1.5; }
  </style>
</head>
<body>
  <main>
    <h1>Access blocked</h1>
    <p>This request was blocked by your organization&rsquo;s web security policy.</p>
    <p style="margin-top:1rem;font-size:0.875rem">If you believe this is an error, contact your administrator.</p>
  </main>
</body>
</html>$html$,
    TRUE
);

-- System CASB application objects (five apps from design §8.2)
INSERT INTO reusable_objects (id, name, type, definition, is_system) VALUES
(
    '00000000-0000-4000-8000-000000000101',
    'CASB: ChatGPT',
    'casb_app_ref',
    '{"app":"chatgpt","hosts":["chat.openai.com","chatgpt.com"],"completeness":"full","actions":["block_upload","block_download","block_send"]}'::jsonb,
    TRUE
),
(
    '00000000-0000-4000-8000-000000000102',
    'CASB: Google Drive',
    'casb_app_ref',
    '{"app":"google_drive","hosts":["drive.google.com","docs.google.com"],"completeness":"full","actions":["block_upload","block_download"]}'::jsonb,
    TRUE
),
(
    '00000000-0000-4000-8000-000000000103',
    'CASB: Microsoft 365',
    'casb_app_ref',
    '{"app":"m365","hosts":["outlook.office.com","onedrive.live.com","*.sharepoint.com"],"completeness":"partial","actions":["block_upload","block_download"]}'::jsonb,
    TRUE
),
(
    '00000000-0000-4000-8000-000000000104',
    'CASB: Slack',
    'casb_app_ref',
    '{"app":"slack","hosts":["app.slack.com","files.slack.com"],"completeness":"partial","actions":["block_upload","block_download","block_message"]}'::jsonb,
    TRUE
),
(
    '00000000-0000-4000-8000-000000000105',
    'CASB: WhatsApp Web',
    'casb_app_ref',
    '{"app":"whatsapp_web","hosts":["web.whatsapp.com"],"completeness":"partial","actions":["block_upload","block_download"]}'::jsonb,
    TRUE
);

-- Default policy pack (enabled baseline + optional disabled RBI sample)
INSERT INTO policies (id, name, description, enabled, priority, sections) VALUES
(
    '00000000-0000-4000-8000-000000000201',
    'Allow local / management exceptions',
    'Bypass inspection for localhost and common private management endpoints used in lab setups.',
    TRUE,
    100,
    '{
      "general": {
        "sources": [],
        "destinations": [
          {"type":"destination_domain","value":"localhost"},
          {"type":"destination_domain","value":"127.0.0.1"}
        ],
        "action": "allow",
        "tls_intercept": false,
        "auth_mode": "disable"
      },
      "web_filtering": {},
      "rbi": {"mode": "not_isolated"},
      "casb": {},
      "antimalware": {"enabled": false}
    }'::jsonb
),
(
    '00000000-0000-4000-8000-000000000202',
    'Anti-malware for broad web',
    'Scan request/response bodies via ClamAV for general web traffic when size budget allows.',
    TRUE,
    500,
    '{
      "general": {
        "sources": [],
        "destinations": [],
        "action": "allow",
        "tls_intercept": true,
        "auth_mode": "disable"
      },
      "web_filtering": {},
      "rbi": {"mode": "not_isolated"},
      "casb": {},
      "antimalware": {"enabled": true, "fail_mode": "fail_open", "max_scan_bytes": 26214400}
    }'::jsonb
),
(
    '00000000-0000-4000-8000-000000000203',
    'Default allow and log',
    'Baseline allow with TLS interception so the product is useful immediately after setup.',
    TRUE,
    900,
    '{
      "general": {
        "sources": [],
        "destinations": [],
        "action": "allow",
        "tls_intercept": true,
        "auth_mode": "disable"
      },
      "web_filtering": {},
      "rbi": {"mode": "not_isolated"},
      "casb": {},
      "antimalware": {"enabled": false}
    }'::jsonb
),
(
    '00000000-0000-4000-8000-000000000204',
    'Sample RBI isolation (disabled)',
    'Example rule that isolates matching destinations. Disabled by default — enable and set destinations when ready.',
    FALSE,
    400,
    '{
      "general": {
        "sources": [],
        "destinations": [
          {"type":"destination_domain","value":"example.com"}
        ],
        "action": "allow",
        "tls_intercept": true,
        "auth_mode": "disable"
      },
      "web_filtering": {},
      "rbi": {
        "mode": "isolated",
        "block_copy_from_site": true,
        "block_copy_to_site": true
      },
      "casb": {},
      "antimalware": {"enabled": false}
    }'::jsonb
);
