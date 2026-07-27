import { useEffect, useState } from "react";
import { getClientSetup } from "../api";
import type { ClientSetup } from "../types";
import {
  Alert,
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  CodeBlock,
  EmptyState,
  PageHeader,
  Spinner,
} from "../components/ui";

export function ClientSetupPage() {
  const [data, setData] = useState<ClientSetup | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await getClientSetup();
        if (!cancelled) setData(res);
      } catch (err) {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load client setup");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) return <Spinner />;
  if (error) return <Alert>{error}</Alert>;
  if (!data) {
    return (
      <EmptyState
        title="Client setup unavailable"
        description="Could not load client configuration guidance."
      />
    );
  }

  return (
    <div>
      <PageHeader
        title="Client setup"
        description="Install the CA, configure proxy/PAC, and troubleshoot common TLS issues."
      />

      <div className="mb-6 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Proxy" description="Explicit forward proxy endpoint." />
          <CardBody className="space-y-2 text-sm">
            <div>
              <span className="text-slate-500">Listen: </span>
              <code>{data.proxy.listen || "—"}</code>
            </div>
            <div>
              <span className="text-slate-500">Host: </span>
              <code>{data.proxy.host}</code>
            </div>
            <div>
              <span className="text-slate-500">Port: </span>
              <code>{data.proxy.port}</code>
            </div>
            <div>
              <Badge tone="info">{data.proxy.type || "explicit"}</Badge>
            </div>
            <p className="text-slate-500">
              Replace <code>PROXY_HOST</code> with the address clients can reach.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Certificate authority"
            description={data.ca.download_note}
          />
          <CardBody className="space-y-3">
            {data.ca.active && data.ca.certificate ? (
              <>
                <div className="text-sm">
                  <div className="font-medium">{data.ca.certificate.name}</div>
                  <div className="font-mono text-xs text-slate-500">
                    {data.ca.certificate.fingerprint_sha256}
                  </div>
                </div>
                {data.ca.download_url ? (
                  <a href={data.ca.download_url}>
                    <Button type="button">Download CA PEM</Button>
                  </a>
                ) : null}
              </>
            ) : (
              <EmptyState
                title="No active CA"
                description="Generate a CA under Settings → Certificates first."
              />
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mb-6">
        <CardHeader title="Trust instructions" />
        <CardBody className="space-y-3">
          {data.ca.trust_instructions ? (
            Object.entries(data.ca.trust_instructions).map(([k, v]) => (
              <div key={k}>
                <div className="text-sm font-medium text-slate-800">
                  {k.replace(/_/g, " ")}
                </div>
                <p className="text-sm text-slate-600">{v}</p>
              </div>
            ))
          ) : (
            <p className="text-sm text-slate-500">No instructions available.</p>
          )}
        </CardBody>
      </Card>

      <Card className="mb-6">
        <CardHeader
          title="PAC file"
          description={data.pac.note}
          actions={
            <Button
              size="sm"
              variant="outline"
              onClick={async () => {
                if (!data.pac.snippet) return;
                await navigator.clipboard.writeText(data.pac.snippet);
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          }
        />
        <CardBody>
          <CodeBlock>{data.pac.snippet || "// no PAC snippet"}</CodeBlock>
        </CardBody>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="MDM / GPO notes" />
          <CardBody>
            <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
              {(data.mdm_gpo_notes || []).map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Troubleshooting" />
          <CardBody>
            <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
              {(data.troubleshooting || []).map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
