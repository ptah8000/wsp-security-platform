export type AdminUser = {
  id: string;
  username: string;
  display_name?: string;
  role: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
  last_login_at?: string;
};

export type SetupStatus = {
  setup_completed: boolean;
  has_admin: boolean;
  has_ca: boolean;
  steps: string[];
};

export type HealthStatus = "healthy" | "degraded" | "critical" | string;

export type HealthComponent = {
  name: string;
  status: HealthStatus;
  message?: string;
  detail?: unknown;
};

export type HealthReport = {
  status: HealthStatus;
  version?: string;
  uptime_sec?: number;
  go_version?: string;
  num_goroutine?: number;
  components?: HealthComponent[];
  checked_at?: string;
  message?: string;
};

export type Setting = {
  key: string;
  value: unknown;
  updated_at?: string;
};

export type CertificateMeta = {
  id: string;
  name: string;
  kind: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  is_active: boolean;
  created_at?: string;
};

export type BlockPage = {
  id: string;
  name: string;
  html: string;
  is_system: boolean;
  created_at?: string;
  updated_at?: string;
};

export type ReusableObject = {
  id: string;
  name: string;
  type: string;
  definition: Record<string, unknown> | string;
  is_system: boolean;
  created_at?: string;
  updated_at?: string;
};

export type Condition = {
  type: string;
  value?: string;
  object_id?: string;
  regex?: string;
};

export type HeaderMod = {
  op: string;
  target: string;
  name: string;
  value?: string;
};

export type CASBRestriction = {
  app: string;
  actions: string[];
  mime_types?: string[];
  extensions?: string[];
};

export type RuleSections = {
  general?: {
    sources?: Condition[];
    destinations?: Condition[];
    action?: "allow" | "block" | string;
    block_page_id?: string;
    block_reason?: string;
    tls_intercept?: boolean;
    auth_mode?: string;
  };
  web_filtering?: {
    sources?: Condition[];
    destinations?: Condition[];
    methods?: string[];
    protocols?: string[];
    header_mods?: HeaderMod[];
  };
  rbi?: {
    mode?: string;
    block_copy_from_site?: boolean;
    block_copy_to_site?: boolean;
  };
  casb?: {
    restrictions?: CASBRestriction[];
  };
  antimalware?: {
    enabled?: boolean;
    fail_mode?: string;
    max_scan_bytes?: number;
  };
};

export type Policy = {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  sections: RuleSections | string;
  created_at?: string;
  updated_at?: string;
};

export type SimulateDecision = {
  url_categories?: string[];
  final_action?: string;
  block_reason?: string;
  block_page_id?: string;
  tls_intercept?: boolean;
  auth_mode?: string;
  rbi_isolated?: boolean;
  rbi_block_copy_from?: boolean;
  rbi_block_copy_to?: boolean;
  malware_scan?: boolean;
  casb?: CASBRestriction[];
  header_mods?: HeaderMod[];
  matched_rule_ids?: string[];
  evaluated_rule_ids?: string[];
};

export type RequestLog = {
  id: string;
  session_id?: string;
  request_id: string;
  ts: string;
  client_ip?: string;
  username?: string;
  user_agent?: string;
  method?: string;
  scheme?: string;
  host?: string;
  path?: string;
  url?: string;
  decision?: string;
  block_reason?: string;
  matched_rule_ids?: string[];
  error?: string;
};

export type BrowsingSession = {
  id: string;
  started_at: string;
  ended_at?: string;
  client_ip?: string;
  username?: string;
  user_agent?: string;
  summary?: unknown;
};

export type AuditEntry = {
  id: string;
  ts: string;
  actor_user_id?: string;
  actor_username?: string;
  action: string;
  target_type?: string;
  target_id?: string;
  summary?: string;
  detail?: unknown;
  ip?: string;
};

export type ClientSetup = {
  proxy: {
    listen?: string;
    host?: string;
    port?: string;
    type?: string;
  };
  ca: {
    active: boolean;
    certificate?: CertificateMeta | null;
    download_url?: string;
    download_note?: string;
    trust_instructions?: Record<string, string>;
  };
  pac: {
    snippet?: string;
    note?: string;
  };
  mdm_gpo_notes?: string[];
  troubleshooting?: string[];
};

export type ApiError = {
  error: string;
  status: number;
};
