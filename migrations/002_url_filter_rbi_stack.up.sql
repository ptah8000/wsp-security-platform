-- Layered web filter: Block → Trusted allow → Isolate (RBI) → Malware.
-- RBI sits behind URL filtering (first explicit rbi.mode wins).

-- Disable legacy sample RBI rule if present.
UPDATE policies
SET enabled = FALSE,
    name = 'Sample RBI isolation (legacy, disabled)',
    description = 'Replaced by layered URL-filter + RBI stack (migration 002).',
    updated_at = NOW()
WHERE id = '00000000-0000-4000-8000-000000000204';

-- Retire old broad allow/malware rules in favor of the layered stack.
UPDATE policies
SET enabled = FALSE,
    priority = 950,
    description = COALESCE(description, '') || ' [superseded by layered URL-filter stack]',
    updated_at = NOW()
WHERE id IN (
  '00000000-0000-4000-8000-000000000202',
  '00000000-0000-4000-8000-000000000203'
);

-- System objects: URL categories (documentation + picker; matching is built-in).
INSERT INTO reusable_objects (id, name, type, definition, is_system) VALUES
(
  '00000000-0000-4000-8000-000000000110',
  'URL category: malware',
  'url_category',
  '{"category":"malware","action_hint":"block"}'::jsonb,
  TRUE
),
(
  '00000000-0000-4000-8000-000000000111',
  'URL category: trusted_productivity',
  'url_category',
  '{"category":"trusted_productivity","action_hint":"allow_direct"}'::jsonb,
  TRUE
),
(
  '00000000-0000-4000-8000-000000000112',
  'URL category: uncategorized',
  'url_category',
  '{"category":"uncategorized","action_hint":"isolate"}'::jsonb,
  TRUE
)
ON CONFLICT (id) DO NOTHING;

-- Layered policy pack (idempotent upsert by fixed UUIDs).
INSERT INTO policies (id, name, description, enabled, priority, sections) VALUES
(
  '00000000-0000-4000-8000-000000000210',
  'URL filter: Block malware & phishing',
  'Layer 1 — Block destinations in the malware URL category. Stops evaluation (no RBI needed).',
  TRUE,
  120,
  '{
    "general": {
      "sources": [],
      "destinations": [{"type":"url_category","value":"malware"}],
      "action": "block",
      "block_reason": "Blocked by URL filter: malware / phishing category",
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
  '00000000-0000-4000-8000-000000000211',
  'URL filter: Block adult content',
  'Layer 1b — Block adult category destinations.',
  TRUE,
  130,
  '{
    "general": {
      "sources": [],
      "destinations": [{"type":"url_category","value":"adult"}],
      "action": "block",
      "block_reason": "Blocked by URL filter: adult category",
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
  '00000000-0000-4000-8000-000000000212',
  'URL filter: Allow trusted productivity (direct)',
  'Layer 2 — Trusted business SaaS: allow without RBI (locks isolation off), TLS intercept + malware scan.',
  TRUE,
  200,
  '{
    "general": {
      "sources": [],
      "destinations": [{"type":"url_category","value":"trusted_productivity"}],
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
  '00000000-0000-4000-8000-000000000213',
  'URL filter: Isolate news & media (RBI)',
  'Layer 3a — News sites via Remote Browser Isolation (after block/trusted filters).',
  TRUE,
  300,
  '{
    "general": {
      "sources": [],
      "destinations": [{"type":"url_category","value":"news_media"}],
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
),
(
  '00000000-0000-4000-8000-000000000214',
  'URL filter: Isolate social, streaming, gambling (RBI)',
  'Layer 3b — Higher-risk consumer categories isolated after URL filter match.',
  TRUE,
  310,
  '{
    "general": {
      "sources": [],
      "destinations": [
        {"type":"url_category","value":"social_media"},
        {"type":"url_category","value":"streaming"},
        {"type":"url_category","value":"gambling"}
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
),
(
  '00000000-0000-4000-8000-000000000215',
  'URL filter: Isolate uncategorized web (RBI)',
  'Layer 3c — Everything not categorized as trusted/malware/adult: isolate. RBI sits behind earlier filters.',
  TRUE,
  320,
  '{
    "general": {
      "sources": [],
      "destinations": [{"type":"url_category","value":"uncategorized"}],
      "action": "allow",
      "tls_intercept": true,
      "auth_mode": "disable"
    },
    "web_filtering": {},
    "rbi": {
      "mode": "isolated",
      "block_copy_from_site": true,
      "block_copy_to_site": false
    },
    "casb": {},
    "antimalware": {"enabled": false}
  }'::jsonb
),
(
  '00000000-0000-4000-8000-000000000216',
  'Anti-malware for non-isolated allow traffic',
  'Layer 4 — Scan bodies when traffic was allowed without isolation (trusted/default).',
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
    "rbi": {},
    "casb": {},
    "antimalware": {"enabled": true, "fail_mode": "fail_open", "max_scan_bytes": 26214400}
  }'::jsonb
)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  enabled = EXCLUDED.enabled,
  priority = EXCLUDED.priority,
  sections = EXCLUDED.sections,
  updated_at = NOW();
