import { Fragment, useCallback, useState, type FormEvent } from "react";
import { getSessionDetail, searchLogs, type LogQuery } from "../api";
import type { BrowsingSession, RequestLog } from "../types";
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
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";

export function LogsPage() {
  const [filters, setFilters] = useState<LogQuery>({
    limit: 50,
    client_ip: "",
    username: "",
    host: "",
    decision: "",
  });
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [session, setSession] = useState<{
    session: BrowsingSession;
    logs: RequestLog[];
  } | null>(null);
  const [sessionLoading, setSessionLoading] = useState(false);

  const load = useCallback(async (q: LogQuery) => {
    setLoading(true);
    setError(null);
    try {
      setLogs(await searchLogs(q));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }, []);

  async function onSearch(e?: FormEvent) {
    e?.preventDefault();
    await load(filters);
  }

  async function toggleSession(sessionId?: string) {
    if (!sessionId) return;
    if (expanded === sessionId) {
      setExpanded(null);
      setSession(null);
      return;
    }
    setExpanded(sessionId);
    setSessionLoading(true);
    setSession(null);
    try {
      setSession(await getSessionDetail(sessionId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load session");
    } finally {
      setSessionLoading(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Request logs"
        description="Filter proxy traffic and expand browsing sessions."
      />

      <Card className="mb-6">
        <CardHeader title="Filters" />
        <CardBody>
          <form
            className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5"
            onSubmit={(e) => void onSearch(e)}
          >
            <Field label="Client IP">
              <Input
                value={filters.client_ip || ""}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, client_ip: e.target.value }))
                }
              />
            </Field>
            <Field label="Username">
              <Input
                value={filters.username || ""}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, username: e.target.value }))
                }
              />
            </Field>
            <Field label="Host">
              <Input
                value={filters.host || ""}
                onChange={(e) => setFilters((f) => ({ ...f, host: e.target.value }))}
              />
            </Field>
            <Field label="Decision">
              <Select
                value={filters.decision || ""}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, decision: e.target.value }))
                }
              >
                <option value="">Any</option>
                <option value="allow">allow</option>
                <option value="block">block</option>
              </Select>
            </Field>
            <Field label="Limit">
              <Input
                type="number"
                min={1}
                max={500}
                value={filters.limit ?? 50}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, limit: Number(e.target.value) }))
                }
              />
            </Field>
            <div className="flex items-end sm:col-span-2 lg:col-span-5">
              <Button type="submit" disabled={loading}>
                {loading ? "Searching…" : "Search"}
              </Button>
            </div>
          </form>
        </CardBody>
      </Card>

      {error ? (
        <div className="mb-4">
          <Alert>{error}</Alert>
        </div>
      ) : null}

      {loading && logs.length === 0 ? (
        <Spinner />
      ) : logs.length === 0 ? (
        <EmptyState
          title="No logs matched"
          description="Adjust filters or wait for proxy traffic. Click Search to load recent entries."
          action={
            <Button variant="outline" onClick={() => void onSearch()}>
              Load recent
            </Button>
          }
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>Decision</Th>
                  <Th>Method</Th>
                  <Th>Host / URL</Th>
                  <Th>Client</Th>
                  <Th>Session</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {logs.map((log) => (
                  <Fragment key={log.id}>
                    <tr>
                      <Td className="whitespace-nowrap text-xs text-slate-500">
                        {log.ts ? new Date(log.ts).toLocaleString() : "—"}
                      </Td>
                      <Td>
                        <StatusBadge status={log.decision} />
                      </Td>
                      <Td className="font-mono text-xs">{log.method || "—"}</Td>
                      <Td className="max-w-xs truncate">
                        {log.host || log.url || "—"}
                        {log.block_reason ? (
                          <div className="text-xs text-red-600">{log.block_reason}</div>
                        ) : null}
                      </Td>
                      <Td>
                        <div className="text-xs">{log.client_ip || "—"}</div>
                        <div className="text-xs text-slate-400">{log.username}</div>
                      </Td>
                      <Td>
                        {log.session_id ? (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void toggleSession(log.session_id)}
                          >
                            {expanded === log.session_id ? "Hide" : "Expand"}
                          </Button>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </Td>
                    </tr>
                    {expanded === log.session_id && log.session_id ? (
                      <tr>
                        <td colSpan={6} className="bg-slate-50 px-4 py-3">
                          {sessionLoading ? (
                            <Spinner label="Loading session…" />
                          ) : session ? (
                            <div className="space-y-2 text-sm">
                              <div className="flex flex-wrap gap-2">
                                <Badge tone="info">session {session.session.id}</Badge>
                                <Badge tone="neutral">
                                  {session.session.client_ip || "no-ip"}
                                </Badge>
                                {session.session.username ? (
                                  <Badge>{session.session.username}</Badge>
                                ) : null}
                              </div>
                              <div className="text-xs text-slate-500">
                                Started{" "}
                                {new Date(session.session.started_at).toLocaleString()}
                                {session.session.ended_at
                                  ? ` · Ended ${new Date(session.session.ended_at).toLocaleString()}`
                                  : ""}
                              </div>
                              <div className="max-h-48 overflow-y-auto rounded border border-slate-200 bg-white">
                                <ul className="divide-y divide-slate-100 text-xs">
                                  {session.logs.map((sl) => (
                                    <li
                                      key={sl.id}
                                      className="flex flex-wrap gap-2 px-2 py-1.5"
                                    >
                                      <StatusBadge status={sl.decision} />
                                      <span className="font-mono">{sl.method}</span>
                                      <span className="truncate">{sl.host || sl.url}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          ) : (
                            <span className="text-sm text-slate-500">
                              Session detail unavailable.
                            </span>
                          )}
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                ))}
              </tbody>
            </Table>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
