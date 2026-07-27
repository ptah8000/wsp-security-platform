import type {
  AdminUser,
  AuditEntry,
  BlockPage,
  BrowsingSession,
  CertificateMeta,
  ClientSetup,
  HealthReport,
  Policy,
  RequestLog,
  ReusableObject,
  Setting,
  SetupStatus,
  SimulateDecision,
} from "./types";

const BASE = "/api/v1";

export class ApiClientError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.body = body;
  }
}

async function parseJSON(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "error" in body) {
    const e = (body as { error: unknown }).error;
    if (typeof e === "string" && e) return e;
  }
  return fallback;
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: "include",
    headers,
  });

  if (res.status === 204) {
    return undefined as T;
  }

  const body = await parseJSON(res);
  if (!res.ok) {
    throw new ApiClientError(
      res.status,
      errorMessage(body, res.statusText || "Request failed"),
      body,
    );
  }
  return body as T;
}

// --- Setup ---

export const getSetupStatus = () => api<SetupStatus>("/setup/status");

export const setupAdmin = (body: {
  username: string;
  password: string;
  display_name?: string;
}) =>
  api("/setup/admin", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const setupCA = (body: { name?: string }) =>
  api<CertificateMeta>("/setup/ca", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const setupNetwork = (body: { dns_servers: string[] }) =>
  api("/setup/network", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const setupComplete = () =>
  api<{ setup_completed: boolean; message?: string }>("/setup/complete", {
    method: "POST",
    body: JSON.stringify({}),
  });

// --- Auth ---

export const login = (username: string, password: string) =>
  api<{ user: AdminUser }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

export const logout = () =>
  api<{ ok: boolean }>("/auth/logout", { method: "POST" });

export const me = () => api<AdminUser>("/auth/me");

// --- Health ---

export const getHealth = () => api<HealthReport>("/health");

// --- Users ---

export const listUsers = () =>
  api<{ users: AdminUser[] }>("/users").then((r) => r.users ?? []);

export const createUser = (body: {
  username: string;
  password: string;
  display_name?: string;
  role?: string;
}) =>
  api<AdminUser>("/users", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const updateUser = (
  id: string,
  body: {
    display_name?: string;
    password?: string;
    role?: string;
    enabled?: boolean;
  },
) =>
  api<AdminUser>(`/users/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });

export const deleteUser = (id: string) =>
  api<void>(`/users/${id}`, { method: "DELETE" });

// --- Certificates ---

export const listCertificates = () =>
  api<{ certificates: CertificateMeta[] }>("/certificates").then(
    (r) => r.certificates ?? [],
  );

export const generateCA = (name?: string) =>
  api<CertificateMeta>("/certificates/generate", {
    method: "POST",
    body: JSON.stringify({ name: name || "WSP Root CA" }),
  });

// --- Settings ---

export const listSettings = () =>
  api<{ settings: Setting[] }>("/settings").then((r) => r.settings ?? []);

export const putSetting = (key: string, value: unknown) =>
  api<Setting>(`/settings/${encodeURIComponent(key)}`, {
    method: "PUT",
    body: JSON.stringify({ value }),
  });

// --- Block pages ---

export const listBlockPages = () =>
  api<{ block_pages: BlockPage[] }>("/block-pages").then(
    (r) => r.block_pages ?? [],
  );

export const createBlockPage = (body: { name: string; html: string }) =>
  api<BlockPage>("/block-pages", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const updateBlockPage = (
  id: string,
  body: { name: string; html: string },
) =>
  api<BlockPage>(`/block-pages/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });

export const deleteBlockPage = (id: string) =>
  api<void>(`/block-pages/${id}`, { method: "DELETE" });

// --- Objects ---

export const listObjects = () =>
  api<{ objects: ReusableObject[] }>("/objects").then((r) => r.objects ?? []);

export const createObject = (body: {
  name: string;
  type: string;
  definition: unknown;
}) =>
  api<ReusableObject>("/objects", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const updateObject = (
  id: string,
  body: { name?: string; type?: string; definition?: unknown },
) =>
  api<ReusableObject>(`/objects/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });

export const deleteObject = (id: string) =>
  api<void>(`/objects/${id}`, { method: "DELETE" });

// --- Policies ---

export const listPolicies = () =>
  api<{ policies: Policy[] }>("/policies").then((r) => r.policies ?? []);

export const getPolicy = (id: string) => api<Policy>(`/policies/${id}`);

export const createPolicy = (body: {
  name: string;
  description?: string;
  enabled?: boolean;
  priority?: number;
  sections?: unknown;
}) =>
  api<Policy>("/policies", {
    method: "POST",
    body: JSON.stringify(body),
  });

export const updatePolicy = (
  id: string,
  body: {
    name?: string;
    description?: string;
    enabled?: boolean;
    priority?: number;
    sections?: unknown;
  },
) =>
  api<Policy>(`/policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });

export const deletePolicy = (id: string) =>
  api<void>(`/policies/${id}`, { method: "DELETE" });

export const reorderPolicies = (ordered_ids: string[]) =>
  api<{ policies: Policy[] }>("/policies/reorder", {
    method: "POST",
    body: JSON.stringify({ ordered_ids }),
  }).then((r) => r.policies ?? []);

export const simulatePolicy = (body: {
  client_ip?: string;
  username?: string;
  user_agent?: string;
  method?: string;
  url: string;
}) =>
  api<{ input: unknown; decision: SimulateDecision }>("/policies/simulate", {
    method: "POST",
    body: JSON.stringify(body),
  });

// --- Logs ---

export type LogQuery = {
  client_ip?: string;
  username?: string;
  host?: string;
  decision?: string;
  session_id?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
};

export const searchLogs = (q: LogQuery = {}) => {
  const params = new URLSearchParams();
  Object.entries(q).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString();
  return api<{ logs: RequestLog[] }>(`/logs/requests${qs ? `?${qs}` : ""}`).then(
    (r) => r.logs ?? [],
  );
};

export const getSessionDetail = (id: string) =>
  api<{ session: BrowsingSession; logs: RequestLog[] }>(
    `/logs/sessions/${id}`,
  );

// --- Audit ---

export const listAudit = (q: { action?: string; limit?: number; offset?: number } = {}) => {
  const params = new URLSearchParams();
  Object.entries(q).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString();
  return api<{ audit: AuditEntry[] }>(`/audit${qs ? `?${qs}` : ""}`).then(
    (r) => r.audit ?? [],
  );
};

// --- Export / client setup ---

export const getClientSetup = () => api<ClientSetup>("/client-setup");

export async function downloadConfigExport(): Promise<void> {
  const res = await fetch(`${BASE}/export/config`, { credentials: "include" });
  if (!res.ok) {
    const body = await parseJSON(res);
    throw new ApiClientError(
      res.status,
      errorMessage(body, "Export failed"),
      body,
    );
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "wsp-config-export.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function parseSections(sections: Policy["sections"]): import("./types").RuleSections {
  if (!sections) return {};
  if (typeof sections === "string") {
    try {
      return JSON.parse(sections) as import("./types").RuleSections;
    } catch {
      return {};
    }
  }
  return sections;
}

export function formatJson(value: unknown): string {
  try {
    if (typeof value === "string") {
      try {
        return JSON.stringify(JSON.parse(value), null, 2);
      } catch {
        return value;
      }
    }
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
