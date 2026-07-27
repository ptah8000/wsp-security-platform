import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import {
  ApiClientError,
  createBlockPage,
  createUser,
  deleteBlockPage,
  deleteUser,
  downloadConfigExport,
  formatJson,
  generateCA,
  listBlockPages,
  listCertificates,
  listSettings,
  listUsers,
  putSetting,
  updateBlockPage,
} from "../api";
import type { AdminUser, BlockPage, CertificateMeta, Setting } from "../types";
import {
  Alert,
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Select,
  Spinner,
  Table,
  Td,
  Textarea,
  Th,
  cn,
} from "../components/ui";

const settingsNav = [
  { to: "/settings", end: true, label: "General" },
  { to: "/settings/users", label: "Users" },
  { to: "/settings/certificates", label: "Certificates" },
  { to: "/settings/block-pages", label: "Block pages" },
  { to: "/settings/export", label: "Export" },
];

export function SettingsLayout() {
  return (
    <div>
      <PageHeader
        title="Settings"
        description="Users, certificates, DNS, retention, block pages, and export."
      />
      <div className="mb-6 flex flex-wrap gap-1 border-b border-slate-200">
        {settingsNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "border-b-2 px-3 py-2 text-sm font-medium",
                isActive
                  ? "border-brand-600 text-brand-700"
                  : "border-transparent text-slate-500 hover:text-slate-800",
              )
            }
          >
            {item.label}
          </NavLink>
        ))}
      </div>
      <Outlet />
    </div>
  );
}

export function GeneralSettings() {
  const [settings, setSettings] = useState<Setting[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [dns, setDns] = useState("");
  const [logDays, setLogDays] = useState("30");
  const [auditDays, setAuditDays] = useState("90");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listSettings();
      setSettings(list);
      const map = Object.fromEntries(list.map((s) => [s.key, s.value]));
      const dnsVal = map["dns_servers"];
      if (Array.isArray(dnsVal)) setDns(dnsVal.join(", "));
      else if (typeof dnsVal === "string") setDns(dnsVal);
      if (map["log_retention_days"] != null) setLogDays(String(map["log_retention_days"]));
      if (map["audit_retention_days"] != null)
        setAuditDays(String(map["audit_retention_days"]));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const servers = dns
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await putSetting("dns_servers", servers);
      await putSetting("log_retention_days", Number(logDays));
      await putSetting("audit_retention_days", Number(auditDays));
      setMsg("Settings saved.");
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div className="space-y-6">
      {error ? <Alert>{error}</Alert> : null}
      {msg ? <Alert tone="success">{msg}</Alert> : null}
      <Card>
        <CardHeader title="General" description="DNS resolvers and log retention." />
        <CardBody>
          <form className="max-w-xl space-y-4" onSubmit={save}>
            <Field label="DNS servers" hint="Comma-separated IP addresses.">
              <Input value={dns} onChange={(e) => setDns(e.target.value)} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Request log retention (days)">
                <Input
                  type="number"
                  min={1}
                  max={3650}
                  value={logDays}
                  onChange={(e) => setLogDays(e.target.value)}
                />
              </Field>
              <Field label="Audit log retention (days)">
                <Input
                  type="number"
                  min={1}
                  max={3650}
                  value={auditDays}
                  onChange={(e) => setAuditDays(e.target.value)}
                />
              </Field>
            </div>
            <Button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save"}
            </Button>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="All settings" description="Raw key/value view (read-only)." />
        <CardBody className="p-0">
          <Table>
            <thead>
              <tr>
                <Th>Key</Th>
                <Th>Value</Th>
                <Th>Updated</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {settings.map((s) => (
                <tr key={s.key}>
                  <Td className="font-mono text-xs">{s.key}</Td>
                  <Td>
                    <pre className="max-w-md overflow-x-auto text-xs">
                      {formatJson(s.value)}
                    </pre>
                  </Td>
                  <Td className="text-xs text-slate-500">
                    {s.updated_at ? new Date(s.updated_at).toLocaleString() : "—"}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </CardBody>
      </Card>
    </div>
  );
}

export function UsersSettings() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState("admin");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUsers(await listUsers());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await createUser({
        username,
        password,
        display_name: displayName,
        role,
      });
      setUsername("");
      setPassword("");
      setDisplayName("");
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm("Delete this user?")) return;
    try {
      await deleteUser(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Delete failed");
    }
  }

  if (loading) return <Spinner />;

  return (
    <div className="space-y-6">
      {error ? <Alert>{error}</Alert> : null}
      <Card>
        <CardHeader title="Create user" />
        <CardBody>
          <form className="grid max-w-2xl gap-3 sm:grid-cols-2" onSubmit={onCreate}>
            <Field label="Username">
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </Field>
            <Field label="Display name">
              <Input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </Field>
            <Field label="Password">
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={8}
                required
              />
            </Field>
            <Field label="Role">
              <Select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="admin">admin</option>
                <option value="user">user (proxy auth)</option>
              </Select>
            </Field>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={busy}>
                {busy ? "Creating…" : "Create user"}
              </Button>
            </div>
          </form>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Users" description={`${users.length} total`} />
        <CardBody className="p-0">
          {users.length === 0 ? (
            <div className="p-5">
              <EmptyState
                title="No users"
                description="Create an admin account to manage the platform."
              />
            </div>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Username</Th>
                  <Th>Role</Th>
                  <Th>Status</Th>
                  <Th>Last login</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {users.map((u) => (
                  <tr key={u.id}>
                    <Td>
                      <div className="font-medium">{u.username}</div>
                      <div className="text-xs text-slate-500">{u.display_name}</div>
                    </Td>
                    <Td>
                      <Badge tone="info">{u.role}</Badge>
                    </Td>
                    <Td>
                      <Badge tone={u.enabled ? "success" : "neutral"}>
                        {u.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </Td>
                    <Td className="text-xs text-slate-500">
                      {u.last_login_at
                        ? new Date(u.last_login_at).toLocaleString()
                        : "—"}
                    </Td>
                    <Td>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => void onDelete(u.id)}
                      >
                        Delete
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}

export function CertsSettings() {
  const [certs, setCerts] = useState<CertificateMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("WSP Root CA");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setCerts(await listCertificates());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load certificates");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onGenerate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await generateCA(name);
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Generate failed");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div className="space-y-6">
      {error ? <Alert>{error}</Alert> : null}
      <Card>
        <CardHeader
          title="Generate CA"
          description="Private keys are never exported. Download public PEM from Client setup."
        />
        <CardBody>
          <form className="flex max-w-lg flex-wrap items-end gap-3" onSubmit={onGenerate}>
            <Field label="Name" className="min-w-[240px] flex-1">
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Button type="submit" disabled={busy}>
              {busy ? "Generating…" : "Generate"}
            </Button>
          </form>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Certificates" />
        <CardBody className="p-0">
          {certs.length === 0 ? (
            <div className="p-5">
              <EmptyState
                title="No certificates"
                description="Generate a self-signed CA to enable TLS interception."
              />
            </div>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Fingerprint</Th>
                  <Th>Validity</Th>
                  <Th>Status</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {certs.map((c) => (
                  <tr key={c.id}>
                    <Td>
                      <div className="font-medium">{c.name}</div>
                      <div className="text-xs text-slate-500">{c.kind}</div>
                    </Td>
                    <Td className="max-w-xs truncate font-mono text-xs">
                      {c.fingerprint_sha256}
                    </Td>
                    <Td className="text-xs text-slate-500">
                      {new Date(c.not_before).toLocaleDateString()} –{" "}
                      {new Date(c.not_after).toLocaleDateString()}
                    </Td>
                    <Td>
                      <Badge tone={c.is_active ? "success" : "neutral"}>
                        {c.is_active ? "active" : "inactive"}
                      </Badge>
                    </Td>
                    <Td>
                      <a
                        className="text-sm text-brand-700 hover:underline"
                        href={`/api/v1/certificates/${c.id}/pem`}
                      >
                        Download PEM
                      </a>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardBody>
      </Card>
      <p className="text-sm text-slate-500">
        See also <Link className="text-brand-700 hover:underline" to="/client-setup">Client setup</Link> for trust instructions.
      </p>
    </div>
  );
}

export function BlockPagesSettings() {
  const [pages, setPages] = useState<BlockPage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [html, setHtml] = useState(
    "<!doctype html><title>Blocked</title><h1>Access denied</h1><p>{{.Reason}}</p>",
  );
  const [editId, setEditId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPages(await listBlockPages());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load block pages");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (editId) {
        await updateBlockPage(editId, { name, html });
      } else {
        await createBlockPage({ name, html });
      }
      setName("");
      setEditId(null);
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div className="space-y-6">
      {error ? <Alert>{error}</Alert> : null}
      <Card>
        <CardHeader title={editId ? "Edit block page" : "Create block page"} />
        <CardBody>
          <form className="space-y-3" onSubmit={onSave}>
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} required />
            </Field>
            <Field label="HTML template" hint="Server-side templates may include placeholders.">
              <Textarea
                className="min-h-[160px] font-mono text-xs"
                value={html}
                onChange={(e) => setHtml(e.target.value)}
                required
              />
            </Field>
            <div className="flex gap-2">
              <Button type="submit" disabled={busy}>
                {busy ? "Saving…" : editId ? "Update" : "Create"}
              </Button>
              {editId ? (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setEditId(null);
                    setName("");
                  }}
                >
                  Cancel
                </Button>
              ) : null}
            </div>
          </form>
        </CardBody>
      </Card>
      <Card>
        <CardHeader title="Block pages" />
        <CardBody className="space-y-3">
          {pages.length === 0 ? (
            <EmptyState
              title="No block pages"
              description="Create an HTML page shown when policy blocks a request."
            />
          ) : (
            pages.map((p) => (
              <div
                key={p.id}
                className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-slate-200 p-3"
              >
                <div>
                  <div className="font-medium">{p.name}</div>
                  <div className="mt-1 flex gap-2">
                    {p.is_system ? <Badge tone="info">system</Badge> : null}
                    <span className="font-mono text-xs text-slate-400">{p.id}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  {!p.is_system ? (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          setEditId(p.id);
                          setName(p.name);
                          setHtml(p.html);
                        }}
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={async () => {
                          if (!confirm("Delete block page?")) return;
                          try {
                            await deleteBlockPage(p.id);
                            await load();
                          } catch (err) {
                            setError(
                              err instanceof ApiClientError
                                ? err.message
                                : "Delete failed",
                            );
                          }
                        }}
                      >
                        Delete
                      </Button>
                    </>
                  ) : null}
                </div>
              </div>
            ))
          )}
        </CardBody>
      </Card>
    </div>
  );
}

export function ExportSettings() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  return (
    <Card>
      <CardHeader
        title="Configuration export"
        description="Download a JSON bundle of policies, objects, settings, users (no secrets), and certificate metadata."
      />
      <CardBody className="space-y-4">
        {error ? <Alert>{error}</Alert> : null}
        <p className="text-sm text-slate-600">
          Export is audited. Import is out of scope for v1. Private keys and password
          hashes are never included.
        </p>
        <Button
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              await downloadConfigExport();
            } catch (err) {
              setError(err instanceof ApiClientError ? err.message : "Export failed");
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Exporting…" : "Download config JSON"}
        </Button>
      </CardBody>
    </Card>
  );
}
