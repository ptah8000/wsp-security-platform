import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ApiClientError,
  createPolicy,
  deletePolicy,
  getPolicy,
  listPolicies,
  parseSections,
  reorderPolicies,
  simulatePolicy,
  updatePolicy,
} from "../api";
import type { Policy, RuleSections, SimulateDecision } from "../types";
import {
  Alert,
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Checkbox,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Select,
  Spinner,
  StatusBadge,
  Table,
  Tabs,
  Td,
  Textarea,
  Th,
} from "../components/ui";

const defaultSections = (): RuleSections => ({
  general: {
    sources: [],
    destinations: [],
    action: "allow",
    tls_intercept: true,
    auth_mode: "disable",
    block_reason: "",
  },
  web_filtering: {
    methods: [],
    protocols: [],
    header_mods: [],
  },
  rbi: {
    mode: "not_isolated",
    block_copy_from_site: false,
    block_copy_to_site: false,
  },
  casb: { restrictions: [] },
  antimalware: {
    enabled: false,
    fail_mode: "fail_open",
    max_scan_bytes: 10485760,
  },
});

export function PolicyListPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setPolicies(await listPolicies());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function move(index: number, dir: -1 | 1) {
    const next = index + dir;
    if (next < 0 || next >= policies.length) return;
    const copy = [...policies];
    const [item] = copy.splice(index, 1);
    copy.splice(next, 0, item);
    setPolicies(copy);
    setBusy(true);
    setError(null);
    try {
      const updated = await reorderPolicies(copy.map((p) => p.id));
      setPolicies(updated);
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Reorder failed");
      await load();
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!confirm("Delete this policy?")) return;
    try {
      await deletePolicy(id);
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Delete failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Policies"
        description="Ordered rules evaluated by priority (top first). Use up/down to reorder."
        actions={
          <>
            <Button variant="outline" onClick={() => navigate("/policy/simulate")}>
              Simulate
            </Button>
            <Button onClick={() => navigate("/policy/new")}>New policy</Button>
          </>
        }
      />
      {error ? (
        <div className="mb-4">
          <Alert>{error}</Alert>
        </div>
      ) : null}
      {loading ? (
        <Spinner />
      ) : policies.length === 0 ? (
        <EmptyState
          title="No policies yet"
          description="Create a policy to control allow/block, TLS intercept, RBI, CASB, and malware scanning."
          action={<Button onClick={() => navigate("/policy/new")}>Create policy</Button>}
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th>Order</Th>
                  <Th>Name</Th>
                  <Th>Priority</Th>
                  <Th>Action</Th>
                  <Th>Status</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {policies.map((p, i) => {
                  const sec = parseSections(p.sections);
                  return (
                    <tr key={p.id}>
                      <Td>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busy || i === 0}
                            onClick={() => void move(i, -1)}
                            title="Move up"
                          >
                            ↑
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={busy || i === policies.length - 1}
                            onClick={() => void move(i, 1)}
                            title="Move down"
                          >
                            ↓
                          </Button>
                        </div>
                      </Td>
                      <Td>
                        <Link
                          className="font-medium text-brand-700 hover:underline"
                          to={`/policy/${p.id}`}
                        >
                          {p.name}
                        </Link>
                        {p.description ? (
                          <div className="text-xs text-slate-500">{p.description}</div>
                        ) : null}
                      </Td>
                      <Td className="font-mono text-xs">{p.priority}</Td>
                      <Td>
                        <StatusBadge status={sec.general?.action || "allow"} />
                      </Td>
                      <Td>
                        <Badge tone={p.enabled ? "success" : "neutral"}>
                          {p.enabled ? "enabled" : "disabled"}
                        </Badge>
                      </Td>
                      <Td>
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => navigate(`/policy/${p.id}`)}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => void onDelete(p.id)}
                          >
                            Delete
                          </Button>
                        </div>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

export function PolicyEditorPage() {
  const { id } = useParams();
  const isNew = !id || id === "new";
  const navigate = useNavigate();

  const [loading, setLoading] = useState(!isNew);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("general");

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [priority, setPriority] = useState(500);
  const [sections, setSections] = useState<RuleSections>(defaultSections());
  const [destText, setDestText] = useState("");
  const [sourceText, setSourceText] = useState("");
  const [methodsText, setMethodsText] = useState("");
  const [protocolsText, setProtocolsText] = useState("");
  const [casbJson, setCasbJson] = useState("[]");

  useEffect(() => {
    if (isNew) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const p = await getPolicy(id!);
        if (cancelled) return;
        setName(p.name);
        setDescription(p.description || "");
        setEnabled(p.enabled);
        setPriority(p.priority);
        const sec = { ...defaultSections(), ...parseSections(p.sections) };
        setSections(sec);
        setSourceText(
          (sec.general?.sources || [])
            .map((c) => c.value || c.regex || "")
            .filter(Boolean)
            .join("\n"),
        );
        setDestText(
          (sec.general?.destinations || [])
            .map((c) => c.value || c.regex || "")
            .filter(Boolean)
            .join("\n"),
        );
        setMethodsText((sec.web_filtering?.methods || []).join(", "));
        setProtocolsText((sec.web_filtering?.protocols || []).join(", "));
        setCasbJson(
          JSON.stringify(sec.casb?.restrictions || [], null, 2),
        );
      } catch (err) {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load policy");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id, isNew]);

  function buildSections(): RuleSections {
    const sources = sourceText
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((value) => ({
        type: value.includes("/") ? "source_ip" : "source_user",
        value,
      }));
    const destinations = destText
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((value) => {
        if (value.startsWith("regex:")) {
          return { type: "destination_regex", regex: value.slice(6), value: value.slice(6) };
        }
        if (value.includes("://") || value.startsWith("/")) {
          return { type: "destination_url", value };
        }
        return { type: "destination_domain", value };
      });

    let restrictions = sections.casb?.restrictions || [];
    try {
      restrictions = JSON.parse(casbJson);
    } catch {
      // keep previous
    }

    return {
      ...sections,
      general: {
        ...sections.general,
        sources,
        destinations,
      },
      web_filtering: {
        ...sections.web_filtering,
        methods: methodsText
          .split(/[,\s]+/)
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean),
        protocols: protocolsText
          .split(/[,\s]+/)
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      },
      casb: { restrictions },
    };
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = {
        name,
        description,
        enabled,
        priority,
        sections: buildSections(),
      };
      if (isNew) {
        const created = await createPolicy(body);
        navigate(`/policy/${created.id}`, { replace: true });
      } else {
        await updatePolicy(id!, body);
        navigate("/policy");
      }
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  const tabs = useMemo(
    () => [
      { id: "general", label: "General" },
      { id: "web", label: "Web" },
      { id: "rbi", label: "RBI" },
      { id: "casb", label: "CASB" },
      { id: "malware", label: "Malware" },
    ],
    [],
  );

  if (loading) return <Spinner />;

  return (
    <div>
      <PageHeader
        title={isNew ? "New policy" : "Edit policy"}
        description="Progressive disclosure: configure only the sections you need."
        actions={
          <Button variant="outline" onClick={() => navigate("/policy")}>
            Back to list
          </Button>
        }
      />
      {error ? (
        <div className="mb-4">
          <Alert>{error}</Alert>
        </div>
      ) : null}

      <form onSubmit={onSave} className="space-y-4">
        <Card>
          <CardBody className="grid gap-4 sm:grid-cols-2">
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} required />
            </Field>
            <Field label="Priority" hint="Lower values evaluate first.">
              <Input
                type="number"
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
              />
            </Field>
            <Field label="Description" className="sm:col-span-2">
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </Field>
            <Checkbox
              checked={enabled}
              onChange={setEnabled}
              label="Enabled"
            />
          </CardBody>
        </Card>

        <Card>
          <div className="px-5 pt-3">
            <Tabs tabs={tabs} active={tab} onChange={setTab} />
          </div>
          <CardBody className="space-y-4">
            {tab === "general" && (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field
                    label="Sources"
                    hint="One per line: username or CIDR (auto-detected)."
                  >
                    <Textarea
                      className="font-mono text-xs"
                      value={sourceText}
                      onChange={(e) => setSourceText(e.target.value)}
                      placeholder={"alice\n10.0.0.0/8"}
                    />
                  </Field>
                  <Field
                    label="Destinations"
                    hint="One per line: domain, URL, or regex:pattern"
                  >
                    <Textarea
                      className="font-mono text-xs"
                      value={destText}
                      onChange={(e) => setDestText(e.target.value)}
                      placeholder={"example.com\nhttps://api.example.com/*\nregex:.*\\.evil\\..*"}
                    />
                  </Field>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  <Field label="Action">
                    <Select
                      value={sections.general?.action || "allow"}
                      onChange={(e) =>
                        setSections((s) => ({
                          ...s,
                          general: { ...s.general, action: e.target.value },
                        }))
                      }
                    >
                      <option value="allow">allow</option>
                      <option value="block">block</option>
                    </Select>
                  </Field>
                  <Field label="Auth mode">
                    <Select
                      value={sections.general?.auth_mode || "disable"}
                      onChange={(e) =>
                        setSections((s) => ({
                          ...s,
                          general: { ...s.general, auth_mode: e.target.value },
                        }))
                      }
                    >
                      <option value="disable">disable</option>
                      <option value="ip_cached">ip_cached</option>
                      <option value="per_request">per_request</option>
                    </Select>
                  </Field>
                  <div className="flex items-end pb-1">
                    <Checkbox
                      checked={!!sections.general?.tls_intercept}
                      onChange={(v) =>
                        setSections((s) => ({
                          ...s,
                          general: { ...s.general, tls_intercept: v },
                        }))
                      }
                      label="TLS intercept (MITM)"
                    />
                  </div>
                </div>
                <Field label="Block reason">
                  <Input
                    value={sections.general?.block_reason || ""}
                    onChange={(e) =>
                      setSections((s) => ({
                        ...s,
                        general: { ...s.general, block_reason: e.target.value },
                      }))
                    }
                  />
                </Field>
              </>
            )}

            {tab === "web" && (
              <>
                <Field label="HTTP methods" hint="Comma-separated; empty = any.">
                  <Input
                    value={methodsText}
                    onChange={(e) => setMethodsText(e.target.value)}
                    placeholder="GET, POST"
                  />
                </Field>
                <Field label="Protocols" hint="http, https; empty = any.">
                  <Input
                    value={protocolsText}
                    onChange={(e) => setProtocolsText(e.target.value)}
                    placeholder="http, https"
                  />
                </Field>
                <p className="text-sm text-slate-500">
                  Advanced header modifications can be added via API/export for v1 advanced cases.
                </p>
              </>
            )}

            {tab === "rbi" && (
              <>
                <Field label="RBI mode">
                  <Select
                    value={sections.rbi?.mode || "not_isolated"}
                    onChange={(e) =>
                      setSections((s) => ({
                        ...s,
                        rbi: { ...s.rbi, mode: e.target.value },
                      }))
                    }
                  >
                    <option value="not_isolated">not_isolated</option>
                    <option value="isolated">isolated</option>
                  </Select>
                </Field>
                <Checkbox
                  checked={!!sections.rbi?.block_copy_from_site}
                  onChange={(v) =>
                    setSections((s) => ({
                      ...s,
                      rbi: { ...s.rbi, block_copy_from_site: v },
                    }))
                  }
                  label="Block copy from site"
                />
                <Checkbox
                  checked={!!sections.rbi?.block_copy_to_site}
                  onChange={(v) =>
                    setSections((s) => ({
                      ...s,
                      rbi: { ...s.rbi, block_copy_to_site: v },
                    }))
                  }
                  label="Block copy to site"
                />
              </>
            )}

            {tab === "casb" && (
              <Field
                label="CASB restrictions (JSON)"
                hint='Array of { "app": "chatgpt", "actions": ["upload"] }'
              >
                <Textarea
                  className="min-h-[180px] font-mono text-xs"
                  value={casbJson}
                  onChange={(e) => setCasbJson(e.target.value)}
                />
              </Field>
            )}

            {tab === "malware" && (
              <>
                <Checkbox
                  checked={!!sections.antimalware?.enabled}
                  onChange={(v) =>
                    setSections((s) => ({
                      ...s,
                      antimalware: { ...s.antimalware, enabled: v },
                    }))
                  }
                  label="Enable malware scan for matching traffic"
                />
                <Field label="Fail mode">
                  <Select
                    value={sections.antimalware?.fail_mode || "fail_open"}
                    onChange={(e) =>
                      setSections((s) => ({
                        ...s,
                        antimalware: { ...s.antimalware, fail_mode: e.target.value },
                      }))
                    }
                  >
                    <option value="fail_open">fail_open</option>
                    <option value="fail_closed">fail_closed</option>
                  </Select>
                </Field>
                <Field label="Max scan bytes">
                  <Input
                    type="number"
                    value={sections.antimalware?.max_scan_bytes ?? 10485760}
                    onChange={(e) =>
                      setSections((s) => ({
                        ...s,
                        antimalware: {
                          ...s.antimalware,
                          max_scan_bytes: Number(e.target.value),
                        },
                      }))
                    }
                  />
                </Field>
              </>
            )}
          </CardBody>
        </Card>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => navigate("/policy")}>
            Cancel
          </Button>
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : isNew ? "Create policy" : "Save changes"}
          </Button>
        </div>
      </form>
    </div>
  );
}

export function PolicySimulatePage() {
  const [url, setUrl] = useState("https://example.com/");
  const [method, setMethod] = useState("GET");
  const [clientIp, setClientIp] = useState("10.0.0.5");
  const [username, setUsername] = useState("");
  const [userAgent, setUserAgent] = useState("Mozilla/5.0");
  const [result, setResult] = useState<SimulateDecision | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await simulatePolicy({
        url,
        method,
        client_ip: clientIp,
        username,
        user_agent: userAgent,
      });
      setResult(res.decision);
    } catch (err) {
      setResult(null);
      setError(err instanceof ApiClientError ? err.message : "Simulation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Policy simulation"
        description="Evaluate a synthetic request against the current policy set without proxy traffic."
        actions={
          <Button variant="outline" onClick={() => history.back()}>
            Back
          </Button>
        }
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Request" />
          <CardBody>
            <form className="space-y-3" onSubmit={onSubmit}>
              {error ? <Alert>{error}</Alert> : null}
              <Field label="URL">
                <Input value={url} onChange={(e) => setUrl(e.target.value)} required />
              </Field>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Method">
                  <Select value={method} onChange={(e) => setMethod(e.target.value)}>
                    {["GET", "POST", "PUT", "DELETE", "CONNECT", "HEAD"].map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Client IP">
                  <Input
                    value={clientIp}
                    onChange={(e) => setClientIp(e.target.value)}
                  />
                </Field>
              </div>
              <Field label="Username">
                <Input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </Field>
              <Field label="User-Agent">
                <Input
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                />
              </Field>
              <Button type="submit" disabled={busy}>
                {busy ? "Simulating…" : "Run simulation"}
              </Button>
            </form>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Decision" />
          <CardBody>
            {!result ? (
              <EmptyState
                title="No result yet"
                description="Submit a request to see the final action and matched rules."
              />
            ) : (
              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Final action</span>
                  <StatusBadge status={result.final_action} />
                </div>
                {result.block_reason ? (
                  <p>
                    <span className="text-slate-500">Block reason: </span>
                    {result.block_reason}
                  </p>
                ) : null}
                <ul className="space-y-1 text-slate-700">
                  <li>TLS intercept: {String(!!result.tls_intercept)}</li>
                  <li>Auth mode: {result.auth_mode || "—"}</li>
                  <li>RBI isolated: {String(!!result.rbi_isolated)}</li>
                  <li>Malware scan: {String(!!result.malware_scan)}</li>
                </ul>
                <div>
                  <div className="mb-1 font-medium text-slate-800">Matched rules</div>
                  <pre className="overflow-x-auto rounded-md bg-slate-50 p-2 text-xs">
                    {JSON.stringify(result.matched_rule_ids || [], null, 2)}
                  </pre>
                </div>
                <div>
                  <div className="mb-1 font-medium text-slate-800">Full decision</div>
                  <pre className="overflow-x-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
