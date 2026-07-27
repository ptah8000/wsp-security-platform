import { useMemo, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import {
  setupAdmin,
  setupCA,
  setupComplete,
  setupNetwork,
  ApiClientError,
} from "../api";
import { useAuth } from "../auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Field,
  Input,
} from "../components/ui";

const STEPS = [
  { id: "admin", title: "Admin account", desc: "Create the first administrator." },
  { id: "ca", title: "Certificate authority", desc: "Generate a self-signed MITM CA." },
  { id: "network", title: "Network", desc: "Configure DNS resolvers for the gateway." },
  { id: "complete", title: "Finish", desc: "Mark setup complete and open the console." },
] as const;

export function SetupPage() {
  const { setup, refresh } = useAuth();
  const navigate = useNavigate();

  const initialStep = useMemo(() => {
    if (!setup?.has_admin) return 0;
    if (!setup?.has_ca) return 1;
    return 2;
  }, [setup]);

  const [step, setStep] = useState(initialStep);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("Administrator");
  const [caName, setCaName] = useState("WSP Root CA");
  const [dns, setDns] = useState("1.1.1.1, 8.8.8.8");
  const [doneMessage, setDoneMessage] = useState<string | null>(null);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  async function onAdmin(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      await setupAdmin({
        username,
        password,
        display_name: displayName,
      });
      await refresh();
      setStep(1);
    });
  }

  async function onCA(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      await setupCA({ name: caName });
      await refresh();
      setStep(2);
    });
  }

  async function onNetwork(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const dns_servers = dns
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await setupNetwork({ dns_servers });
      setStep(3);
    });
  }

  async function onComplete() {
    await run(async () => {
      const res = await setupComplete();
      setDoneMessage(res.message || "Setup complete.");
      await refresh();
      navigate("/login");
    });
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-brand-50 to-slate-50 px-4 py-10">
      <div className="mx-auto max-w-3xl">
        <div className="mb-8 text-center">
          <div className="text-xs font-semibold uppercase tracking-wider text-brand-600">
            First-run wizard
          </div>
          <h1 className="mt-1 text-3xl font-semibold text-slate-900">
            Set up Web Security Platform
          </h1>
          <p className="mt-2 text-sm text-slate-500">
            Complete these steps once. Management APIs stay locked until setup finishes.
          </p>
        </div>

        <ol className="mb-6 grid gap-2 sm:grid-cols-4">
          {STEPS.map((s, i) => (
            <li
              key={s.id}
              className={`rounded-lg border px-3 py-2 text-sm ${
                i === step
                  ? "border-brand-300 bg-white shadow-sm"
                  : i < step
                    ? "border-emerald-200 bg-emerald-50"
                    : "border-slate-200 bg-white/60"
              }`}
            >
              <div className="flex items-center gap-2">
                <Badge tone={i < step ? "success" : i === step ? "info" : "neutral"}>
                  {i + 1}
                </Badge>
                <span className="font-medium text-slate-800">{s.title}</span>
              </div>
            </li>
          ))}
        </ol>

        {error ? (
          <div className="mb-4">
            <Alert>{error}</Alert>
          </div>
        ) : null}

        <Card>
          <CardHeader
            title={STEPS[step].title}
            description={STEPS[step].desc}
          />
          <CardBody>
            {step === 0 && (
              <form className="space-y-4" onSubmit={onAdmin}>
                <Field label="Username">
                  <Input
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoComplete="username"
                  />
                </Field>
                <Field label="Display name">
                  <Input
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                  />
                </Field>
                <Field label="Password" hint="Minimum 8 characters.">
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={8}
                    autoComplete="new-password"
                  />
                </Field>
                <div className="flex justify-end">
                  <Button type="submit" disabled={busy}>
                    {busy ? "Saving…" : "Create admin"}
                  </Button>
                </div>
              </form>
            )}

            {step === 1 && (
              <form className="space-y-4" onSubmit={onCA}>
                {setup?.has_ca ? (
                  <Alert tone="success">
                    An active CA already exists. You can continue or generate another
                    (the new one becomes active).
                  </Alert>
                ) : null}
                <Field label="CA name">
                  <Input
                    value={caName}
                    onChange={(e) => setCaName(e.target.value)}
                    placeholder="WSP Root CA"
                  />
                </Field>
                <p className="text-sm text-slate-500">
                  The private key is encrypted at rest with <code>WSP_DATA_KEY</code> and
                  is never exported via the API.
                </p>
                <div className="flex justify-between">
                  <Button type="button" variant="ghost" onClick={() => setStep(0)}>
                    Back
                  </Button>
                  <div className="flex gap-2">
                    {setup?.has_ca ? (
                      <Button type="button" variant="outline" onClick={() => setStep(2)}>
                        Skip
                      </Button>
                    ) : null}
                    <Button type="submit" disabled={busy}>
                      {busy ? "Generating…" : "Generate CA"}
                    </Button>
                  </div>
                </div>
              </form>
            )}

            {step === 2 && (
              <form className="space-y-4" onSubmit={onNetwork}>
                <Field
                  label="DNS servers"
                  hint="Comma or space separated. Used for gateway resolution hints."
                >
                  <Input
                    value={dns}
                    onChange={(e) => setDns(e.target.value)}
                    placeholder="1.1.1.1, 8.8.8.8"
                    required
                  />
                </Field>
                <div className="flex justify-between">
                  <Button type="button" variant="ghost" onClick={() => setStep(1)}>
                    Back
                  </Button>
                  <Button type="submit" disabled={busy}>
                    {busy ? "Saving…" : "Save network"}
                  </Button>
                </div>
              </form>
            )}

            {step === 3 && (
              <div className="space-y-4">
                <p className="text-sm text-slate-600">
                  You are ready to finish setup. After completion, sign in with the admin
                  account and open <strong>Client setup</strong> to download the CA and
                  configure browsers.
                </p>
                {doneMessage ? <Alert tone="success">{doneMessage}</Alert> : null}
                <div className="flex justify-between">
                  <Button type="button" variant="ghost" onClick={() => setStep(2)}>
                    Back
                  </Button>
                  <Button type="button" onClick={() => void onComplete()} disabled={busy}>
                    {busy ? "Completing…" : "Complete setup"}
                  </Button>
                </div>
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
