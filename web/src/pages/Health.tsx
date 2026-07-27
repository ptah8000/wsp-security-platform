import { useCallback, useEffect, useState } from "react";
import { getHealth } from "../api";
import type { HealthReport } from "../types";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  PageHeader,
  Spinner,
  StatusBadge,
} from "../components/ui";

function formatUptime(sec?: number) {
  if (sec == null) return "—";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function HealthPage() {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await getHealth());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load health");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div>
      <PageHeader
        title="System health"
        description="Aggregate status of database, gateway, ClamAV, RBI, and process."
        actions={
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            Refresh
          </Button>
        }
      />

      {loading && !report ? <Spinner /> : null}
      {error ? <p className="mb-4 text-sm text-red-600">{error}</p> : null}

      {report ? (
        <>
          <div className="mb-6 grid gap-4 sm:grid-cols-4">
            <Card>
              <CardBody>
                <div className="text-xs uppercase text-slate-500">Overall</div>
                <div className="mt-2">
                  <StatusBadge status={report.status} />
                </div>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <div className="text-xs uppercase text-slate-500">Version</div>
                <div className="mt-2 text-lg font-semibold">{report.version || "—"}</div>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <div className="text-xs uppercase text-slate-500">Uptime</div>
                <div className="mt-2 text-lg font-semibold">
                  {formatUptime(report.uptime_sec)}
                </div>
              </CardBody>
            </Card>
            <Card>
              <CardBody>
                <div className="text-xs uppercase text-slate-500">Goroutines</div>
                <div className="mt-2 text-lg font-semibold">
                  {report.num_goroutine ?? "—"}
                </div>
              </CardBody>
            </Card>
          </div>

          <Card>
            <CardHeader
              title="Components"
              description={
                report.checked_at
                  ? `Last checked ${new Date(report.checked_at).toLocaleString()}`
                  : report.message
              }
            />
            <CardBody className="p-0">
              {!report.components?.length ? (
                <p className="px-5 py-6 text-sm text-slate-500">
                  {report.message || "No component probes configured."}
                </p>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {report.components.map((c) => (
                    <li
                      key={c.name}
                      className="flex flex-wrap items-start justify-between gap-3 px-5 py-3"
                    >
                      <div>
                        <div className="font-medium text-slate-900">{c.name}</div>
                        {c.message ? (
                          <div className="text-sm text-slate-500">{c.message}</div>
                        ) : null}
                        {c.detail != null ? (
                          <pre className="mt-1 max-w-xl overflow-x-auto text-xs text-slate-400">
                            {JSON.stringify(c.detail, null, 2)}
                          </pre>
                        ) : null}
                      </div>
                      <StatusBadge status={c.status} />
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>

          {report.go_version ? (
            <p className="mt-4 text-xs text-slate-400">Runtime {report.go_version}</p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
