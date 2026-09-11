"use client";

/**
 * First-run setup. The only screen reachable before an API token exists —
 * everything else is redirected here by `middleware.ts`.
 *
 * Two steps, and the second is genuinely optional. The token is required: the
 * API refuses every request without one. A model is not — the whole pipeline
 * is deterministic-first and produces a complete report with no model
 * configured at all (§2.5), so the AI step offers a prominent "skip" rather
 * than pretending it is a prerequisite.
 */

import { useEffect, useState } from "react";
import { Button, ErrorNotice, Panel } from "@/components/ui";

interface CatalogEntry {
  id: string;
  label: string;
  kind: string;
  base_url: string;
  default_model: string;
  requires_key: boolean;
  is_local: boolean;
  summary: string;
  key_hint: string;
  key_url: string;
  suggested_models: string[];
  needs_base_url: boolean;
}

/**
 * Leave setup with a full page load, never `router.push`.
 *
 * Arriving here means middleware redirected `/` → `/setup`, and Next's client
 * router cached that redirect. A client-side push replays the cached entry and
 * lands straight back on this page — the button appears dead. Completing setup
 * also changes server state the whole cache was built under (no token → token),
 * so discarding it is correct rather than a workaround.
 */
function leaveSetup(): void {
  window.location.assign("/");
}

export default function SetupPage() {
  const [step, setStep] = useState<"token" | "model">("token");
  return step === "token" ? (
    <TokenStep onDone={() => setStep("model")} />
  ) : (
    <ModelStep />
  );
}

function Shell({
  title,
  intro,
  children,
}: {
  title: string;
  intro: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mx-auto flex max-w-2xl flex-col justify-center py-10">
      <div className="mb-5">
        <h1 className="text-lg font-semibold tracking-[-0.01em]">{title}</h1>
        <p className="mt-1.5 text-[13px] leading-relaxed text-content-muted">{intro}</p>
      </div>
      {children}
    </div>
  );
}

/* ---------------------------------------------------------------- step one */

function TokenStep({ onDone }: { onDone: () => void }) {
  const [phase, setPhase] = useState<"idle" | "working" | "done" | "error">("idle");
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function generate() {
    setPhase("working");
    setError(null);
    try {
      const response = await fetch("/api/setup/bootstrap", { method: "POST" });
      const body = await response.json();
      if (response.status === 409) {
        // A token already exists — someone reopened /setup on a configured
        // deployment. That is not an error worth stranding them on: the one
        // thing this step produces is already done, so go to the step that
        // still has something to offer.
        onDone();
        return;
      }
      if (!response.ok) {
        throw new Error(body.detail ?? `setup failed (HTTP ${response.status})`);
      }
      setToken(body.token as string);
      setPhase("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "setup failed");
      setPhase("error");
    }
  }

  async function copy() {
    if (!token) return;
    await navigator.clipboard.writeText(token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Shell
      title="Set up BARE"
      intro="Step 1 of 2. The API requires a credential and none exists yet. This runs once — it mints the first admin token, saves it for the dashboard to use from now on, and shows it to you a single time."
    >
      <Panel>
        <div className="space-y-4 px-4 py-4">
          {phase !== "done" && (
            <>
              <p className="text-[13px] leading-relaxed text-content-muted">
                You will also want this token if you plan to use the CLI or a CI
                pipeline directly (
                <span className="font-mono text-xs">bare scan --token …</span>
                ) — the dashboard cannot hand it back to you a second time, so copy
                it somewhere safe when it appears below.
              </p>
              <Button variant="primary" onClick={generate} disabled={phase === "working"}>
                {phase === "working" ? "Generating…" : "Generate admin token"}
              </Button>
              {error && <ErrorNotice title="Could not complete setup" detail={error} />}
            </>
          )}

          {phase === "done" && token && (
            <>
              <p className="text-[13px] font-medium text-ok">
                Token created. The dashboard is already using it — save a copy only
                if you need one for the CLI or CI.
              </p>
              <div className="flex items-center gap-2 rounded-md border border-border bg-surface-sunken px-3 py-2">
                <code className="flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs">
                  {token}
                </code>
                <Button onClick={copy}>{copied ? "Copied" : "Copy"}</Button>
              </div>
              <p className="text-[11.5px] leading-relaxed text-content-subtle">
                This is an admin-scoped token. Mint a narrower one for CI (
                <span className="font-mono">bare token create ci --scope ci</span>
                ) and keep this one for the dashboard alone.
              </p>
              <Button variant="primary" onClick={onDone}>
                Next: connect a model
              </Button>
            </>
          )}
        </div>
      </Panel>
    </Shell>
  );
}

/* ---------------------------------------------------------------- step two */

function ModelStep() {
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [chosen, setChosen] = useState<CatalogEntry | null>(null);
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState<string | null>(null);
  const [showEndpoint, setShowEndpoint] = useState(false);

  useEffect(() => {
    fetch("/api/settings/llm/catalog")
      .then((r) => (r.ok ? r.json() : []))
      .then(setCatalog)
      .catch(() => setCatalog([]));
  }, []);

  function choose(entry: CatalogEntry) {
    setChosen(entry);
    setModel(entry.default_model);
    setBaseUrl(entry.base_url);
    setApiKey("");
    setError(null);
    setShowEndpoint(false);
  }

  async function connect() {
    if (!chosen) return;
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/settings/llm/providers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          catalog_id: chosen.id,
          model,
          base_url: baseUrl || null,
          api_key: apiKey || null,
        }),
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? `could not connect (HTTP ${response.status})`);
      }
      setConnected(body.health?.model ?? model);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (connected) {
    return (
      <Shell
        title="Model connected"
        intro="BARE will use it to triage findings, explain them, and summarise runs. You can change any of this later in Settings."
      >
        <Panel>
          <div className="space-y-3 px-4 py-4">
            <p className="text-[13px] text-ok">
              Connected to <span className="font-mono">{connected}</span>.
            </p>
            <p className="text-[12px] leading-relaxed text-content-subtle">
              Every finding still comes from a deterministic rule. The model
              classifies and explains them — it never creates one, and it cannot
              change a severity.
            </p>
            <Button variant="primary" onClick={leaveSetup}>
              Finish
            </Button>
          </div>
        </Panel>
      </Shell>
    );
  }

  return (
    <Shell
      title="Connect a model"
      intro="Step 2 of 2, and entirely optional. BARE is deterministic-first: every finding comes from a rule, and a scan produces a complete report with no model configured at all. A model adds triage, explanations, and run summaries on top."
    >
      <Panel
        title="Providers"
        actions={
          <Button onClick={leaveSetup}>Skip for now</Button>
        }
      >
        <div className="space-y-4 px-4 py-4">
          <div className="grid gap-2 sm:grid-cols-2">
            {catalog.map((entry) => (
              <button
                key={entry.id}
                type="button"
                onClick={() => choose(entry)}
                className={`rounded-md border px-3 py-2.5 text-left transition-colors ${
                  chosen?.id === entry.id
                    ? "border-accent bg-accent-muted"
                    : "border-border hover:border-content-subtle hover:bg-surface-sunken"
                }`}
              >
                <span className="flex items-center gap-1.5 text-[13px] font-medium">
                  {entry.label}
                  {entry.is_local && (
                    <span className="rounded bg-ok/15 px-1 py-px text-[9.5px] uppercase tracking-wider text-ok">
                      local
                    </span>
                  )}
                </span>
                <span className="mt-0.5 block text-[11.5px] leading-relaxed text-content-muted">
                  {entry.summary}
                </span>
              </button>
            ))}
          </div>

          {chosen && (
            <div className="space-y-3 border-t border-border pt-4">
              <Field label="Model">
                <input
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  placeholder="model id"
                  className="w-full rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs"
                />
                {chosen.suggested_models.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {chosen.suggested_models.map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setModel(m)}
                        className="rounded border border-border px-1.5 py-0.5 font-mono text-[10.5px] text-content-muted hover:border-accent hover:text-content"
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                )}
              </Field>

              {/* Most providers need no endpoint: LiteLLM knows where they
                  live, and the model prefix is what routes. Only self-hosted
                  and bring-your-own-gateway entries genuinely require one, so
                  the field is offered rather than demanded. */}
              {(chosen.needs_base_url || chosen.is_local || showEndpoint) && (
                <Field label={chosen.needs_base_url ? "Endpoint" : "Endpoint (optional)"}>
                  <input
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    placeholder="https://…"
                    className="w-full rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs"
                  />
                </Field>
              )}
              {!chosen.needs_base_url && !chosen.is_local && !showEndpoint && (
                <button
                  type="button"
                  onClick={() => setShowEndpoint(true)}
                  className="text-[11.5px] text-content-subtle underline hover:text-content"
                >
                  Use a custom endpoint
                </button>
              )}

              {chosen.requires_key && (
                <Field label="API key">
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder={chosen.key_hint || "paste your key"}
                    className="w-full rounded-md border border-border bg-surface px-3 py-1.5 font-mono text-xs"
                  />
                  <p className="mt-1 text-[11px] text-content-subtle">
                    Stored on the server, never in <span className="font-mono">config/llm.yaml</span>{" "}
                    and never sent to the browser again.
                    {chosen.key_url && (
                      <>
                        {" "}
                        <a
                          href={chosen.key_url}
                          target="_blank"
                          rel="noreferrer"
                          className="underline hover:text-content"
                        >
                          Get a key
                        </a>
                        .
                      </>
                    )}
                  </p>
                </Field>
              )}

              {!chosen.is_local && (
                <p className="rounded border border-high/30 bg-high-bg px-3 py-2 text-[11.5px] leading-relaxed text-high">
                  This is a hosted provider, so connecting it turns on outbound
                  network access for the model layer. Candidate secrets are never
                  sent — the model sees masked values, rule names, entropy, and
                  offsets only. Analyzers stay offline either way.
                </p>
              )}

              <div className="flex items-center gap-2">
                <Button variant="primary" onClick={connect} disabled={busy || !model}>
                  {busy ? "Testing…" : "Connect and test"}
                </Button>
                <span className="text-[11.5px] text-content-subtle">
                  Nothing is saved unless the test succeeds.
                </span>
              </div>

              {error && <ErrorNotice title="Could not connect" detail={error} />}
            </div>
          )}
        </div>
      </Panel>
    </Shell>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <span className="block text-[11px] font-medium uppercase tracking-wider text-content-subtle">
        {label}
      </span>
      <div className="mt-1">{children}</div>
    </div>
  );
}
