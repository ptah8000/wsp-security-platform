import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  ApiClientError,
  createObject,
  deleteObject,
  formatJson,
  listObjects,
  updateObject,
} from "../api";
import type { ReusableObject } from "../types";
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
} from "../components/ui";

const OBJECT_TYPES = [
  "source_ip",
  "source_user",
  "user_agent",
  "destination_domain",
  "destination_url",
  "destination_regex",
  "time_window",
  "header_mod",
  "casb_app_ref",
];

const defaultDefinition = (type: string): string => {
  switch (type) {
    case "source_ip":
      return JSON.stringify({ cidrs: ["10.0.0.0/8"] }, null, 2);
    case "source_user":
      return JSON.stringify({ usernames: ["alice"] }, null, 2);
    case "user_agent":
      return JSON.stringify({ user_agents: ["*curl*"] }, null, 2);
    case "destination_domain":
      return JSON.stringify({ domains: ["example.com"] }, null, 2);
    case "destination_url":
      return JSON.stringify({ urls: ["https://example.com/*"] }, null, 2);
    case "destination_regex":
      return JSON.stringify({ regex: ".*\\.example\\.com" }, null, 2);
    case "casb_app_ref":
      return JSON.stringify(
        { app: "chatgpt", hosts: ["chat.openai.com"], actions: ["upload"] },
        null,
        2,
      );
    default:
      return "{}";
  }
};

export function ObjectsPage() {
  const [objects, setObjects] = useState<ReusableObject[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [editId, setEditId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [type, setType] = useState("destination_domain");
  const [definition, setDefinition] = useState(defaultDefinition("destination_domain"));

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setObjects(await listObjects());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load objects");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function resetForm() {
    setEditId(null);
    setName("");
    setType("destination_domain");
    setDefinition(defaultDefinition("destination_domain"));
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      let def: unknown;
      try {
        def = JSON.parse(definition);
      } catch {
        throw new ApiClientError(400, "Definition must be valid JSON");
      }
      if (editId) {
        await updateObject(editId, { name, type, definition: def });
      } else {
        await createObject({ name, type, definition: def });
      }
      resetForm();
      await load();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Reusable objects"
        description="Named conditions and CASB app references for use in policies."
      />
      {error ? (
        <div className="mb-4">
          <Alert>{error}</Alert>
        </div>
      ) : null}

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title={editId ? "Edit object" : "Create object"} />
          <CardBody>
            <form className="space-y-3" onSubmit={onSave}>
              <Field label="Name">
                <Input value={name} onChange={(e) => setName(e.target.value)} required />
              </Field>
              <Field label="Type">
                <Select
                  value={type}
                  onChange={(e) => {
                    const t = e.target.value;
                    setType(t);
                    if (!editId) setDefinition(defaultDefinition(t));
                  }}
                  disabled={!!editId}
                >
                  {OBJECT_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Definition (JSON)">
                <Textarea
                  className="min-h-[160px] font-mono text-xs"
                  value={definition}
                  onChange={(e) => setDefinition(e.target.value)}
                  required
                />
              </Field>
              <div className="flex gap-2">
                <Button type="submit" disabled={busy}>
                  {busy ? "Saving…" : editId ? "Update" : "Create"}
                </Button>
                {editId ? (
                  <Button type="button" variant="ghost" onClick={resetForm}>
                    Cancel
                  </Button>
                ) : null}
              </div>
            </form>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Guidance"
            description="Objects keep policy rules readable and reusable."
          />
          <CardBody className="space-y-2 text-sm text-slate-600">
            <p>
              Reference objects from policy conditions with type <code>object_ref</code>{" "}
              and an <code>object_id</code> (advanced), or keep simple inline conditions
              in the policy editor.
            </p>
            <p>
              System objects (seeded CASB apps, defaults) cannot be modified or deleted.
            </p>
          </CardBody>
        </Card>
      </div>

      {loading ? (
        <Spinner />
      ) : objects.length === 0 ? (
        <EmptyState
          title="No reusable objects"
          description="Create domain lists, IP ranges, or CASB app refs to share across policies."
        />
      ) : (
        <Card>
          <CardBody className="p-0">
            <Table>
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Type</Th>
                  <Th>Definition</Th>
                  <Th />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {objects.map((o) => (
                  <tr key={o.id}>
                    <Td>
                      <div className="font-medium">{o.name}</div>
                      {o.is_system ? <Badge tone="info">system</Badge> : null}
                    </Td>
                    <Td className="font-mono text-xs">{o.type}</Td>
                    <Td>
                      <pre className="max-w-md overflow-x-auto text-xs text-slate-500">
                        {formatJson(o.definition)}
                      </pre>
                    </Td>
                    <Td>
                      {!o.is_system ? (
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setEditId(o.id);
                              setName(o.name);
                              setType(o.type);
                              setDefinition(formatJson(o.definition));
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={async () => {
                              if (!confirm("Delete object?")) return;
                              try {
                                await deleteObject(o.id);
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
                        </div>
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
