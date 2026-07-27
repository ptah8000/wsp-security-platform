import { useCallback, useEffect, useState, type FormEvent } from "react";
import { formatJson, listAudit } from "../api";
import type { AuditEntry } from "../types";
import {
  Alert,
  Button,
  Card,
  CardBody,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Spinner,
  Table,
  Td,
  Th,
} from "../components/ui";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (filterAction?: string) => {
    setLoading(true);
    setError(null);
    try {
      setEntries(
        await listAudit({
          action: filterAction || undefined,
          limit: 100,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onSearch(e: FormEvent) {
    e.preventDefault();
    await load(action);
  }

  return (
    <div>
      <PageHeader
        title="Audit log"
        description="Admin and system actions recorded by the management plane."
      />

      <form className="mb-6 flex flex-wrap items-end gap-3" onSubmit={(e) => void onSearch(e)}>
        <Field label="Action filter" className="min-w-[220px]">
          <Input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="policy.create"
          />
        </Field>
        <Button type="submit" variant="outline" disabled={loading}>
          Filter
        </Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => {
            setAction("");
            void load();
          }}
        >
          Clear
        </Button>
      </form>

      {error ? (
        <div className="mb-4">
          <Alert>{error}</Alert>
        </div>
      ) : null}

      {loading ? (
        <Spinner />
      ) : entries.length === 0 ? (
        <EmptyState
          title="No audit entries"
          description="Administrative actions (login, policy changes, export) appear here."
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th>Time</Th>
                  <Th>Actor</Th>
                  <Th>Action</Th>
                  <Th>Summary</Th>
                  <Th>Target</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {entries.map((e) => (
                  <tr key={e.id}>
                    <Td className="whitespace-nowrap text-xs text-slate-500">
                      {new Date(e.ts).toLocaleString()}
                    </Td>
                    <Td>
                      <div className="text-sm">{e.actor_username || "system"}</div>
                      <div className="text-xs text-slate-400">{e.ip}</div>
                    </Td>
                    <Td className="font-mono text-xs">{e.action}</Td>
                    <Td className="max-w-sm">
                      <div>{e.summary || "—"}</div>
                      {e.detail != null ? (
                        <pre className="mt-1 max-h-20 overflow-auto text-xs text-slate-400">
                          {formatJson(e.detail)}
                        </pre>
                      ) : null}
                    </Td>
                    <Td className="text-xs text-slate-500">
                      {e.target_type || "—"}
                      {e.target_id ? (
                        <div className="font-mono">{e.target_id}</div>
                      ) : null}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
