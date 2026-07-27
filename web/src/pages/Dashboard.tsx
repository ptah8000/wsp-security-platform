import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getHealth, listPolicies, searchLogs } from "../api";
import type { HealthReport, Policy, RequestLog } from "../types";
import {
  Badge,
  Card,
  CardBody,
  CardHeader,
  PageHeader,
  Spinner,
  StatusBadge,
} from "../components/ui";

export function DashboardPage() {
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [h, p, l] = await Promise.all([
          getHealth(),
          listPolicies(),
          searchLogs({ limit: 8 }),
        ]);
        if (cancelled) return;
        setHealth(h);
        setPolicies(p);
        setLogs(l);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <Spinner />;

  const enabled = policies.filter((p) => p.enabled).length;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Overview of gateway health, policies, and recent traffic."
      />
      {error ? (
        <p className="mb-4 text-sm text-red-600">{error}</p>
      ) : null}

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <Card>
          <CardBody>
            <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
              System health
            </div>
            <div className="mt-2 flex items-center gap-2">
              <StatusBadge status={health?.status} />
              <span className="text-sm text-slate-600">v{health?.version || "—"}</span>
            </div>
            <Link className="mt-3 inline-block text-sm text-brand-700 hover:underline" to="/health">
              View health details →
            </Link>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Policies
            </div>
            <div className="mt-2 text-2xl font-semibold text-slate-900">
              {enabled}
              <span className="text-base font-normal text-slate-400">
                {" "}
                / {policies.length} enabled
              </span>
            </div>
            <Link className="mt-3 inline-block text-sm text-brand-700 hover:underline" to="/policy">
              Manage policies →
            </Link>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Quick links
            </div>
            <ul className="mt-2 space-y-1 text-sm">
              <li>
                <Link className="text-brand-700 hover:underline" to="/client-setup">
                  Client setup &amp; CA download
                </Link>
              </li>
              <li>
                <Link className="text-brand-700 hover:underline" to="/policy/simulate">
                  Policy simulation
                </Link>
              </li>
              <li>
                <Link className="text-brand-700 hover:underline" to="/settings/export">
                  Export configuration
                </Link>
              </li>
            </ul>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Recent requests"
          description="Latest entries from request logs."
          actions={
            <Link className="text-sm text-brand-700 hover:underline" to="/logs">
              Open logs
            </Link>
          }
        />
        <CardBody className="p-0">
          {logs.length === 0 ? (
            <div className="px-5 py-8 text-center text-sm text-slate-500">
              No request logs yet. Point a client at the proxy to see traffic here.
            </div>
          ) : (
            <ul className="divide-y divide-slate-100">
              {logs.map((log) => (
                <li key={log.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
                  <StatusBadge status={log.decision} />
                  <span className="font-mono text-xs text-slate-500">
                    {log.method || "—"}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-slate-800">
                    {log.host || log.url || "—"}
                  </span>
                  <Badge tone="neutral">{log.client_ip || "no-ip"}</Badge>
                  <span className="text-xs text-slate-400">
                    {log.ts ? new Date(log.ts).toLocaleString() : ""}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
