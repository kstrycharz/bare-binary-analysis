"use client";

/**
 * Connect a model provider: pick from the catalog, fill in what it needs, test
 * it, save it.
 *
 * Shared by the setup wizard's optional second step and the Settings page. It
 * used to live only in the wizard, and the wizard's "Skip for now" is a real
 * choice — the pipeline is complete without a model (§2.5) — so skipping it
 * left no screen anywhere that could add one later. Settings even said "add one
 * on this page", with nothing on the page to do it with.
 */

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";
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

export function ConnectProvider({
  title = "Providers",
  description,
  actions,
  onConnected,
}: {
  title?: string;
  description?: string;
  actions?: React.ReactNode;
  /** Called with the model the provider reported, once the test has passed and the config is written. */
  onConnected: (model: string) => void;
}) {
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);
  const [chosen, setChosen] = useState<CatalogEntry | null>(null);
  const [model, setModel] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
      // The key is in the server's store now; do not keep a copy in the page.
      setApiKey("");
      setChosen(null);
      onConnected(body.health?.model ?? model);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title={title} description={description} actions={actions}>
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
  );
}

/**
 * The Settings page's way to add a provider, available whether or not the
 * setup wizard's model step was skipped, and whether or not AI assistance is
 * currently switched on — connecting a provider switches it on, as the wizard
 * does.
 */
export function AddProviderPanel({ hasProviders }: { hasProviders: boolean }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [connected, setConnected] = useState<string | null>(null);

  return (
    <div className="space-y-3">
      {connected && (
        <div className="rounded-md border border-ok/40 bg-ok-bg px-3.5 py-2.5">
          <p className="text-[12.5px] font-medium text-ok">
            Connected to <span className="font-mono">{connected}</span>
            {pending ? " — refreshing…" : ". Every role now routes to it; change that below."}
          </p>
        </div>
      )}
      <ConnectProvider
        title={hasProviders ? "Add another provider" : "Add a provider"}
        description="Tested before anything is saved. Every finding still comes from a deterministic rule; a model only classifies and explains them."
        onConnected={(model) => {
          setConnected(model);
          // Re-render the server component so the provider cards, role routing,
          // and the AI switch all show the configuration that was just written.
          startTransition(() => router.refresh());
        }}
      />
    </div>
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
