"use client";

/**
 * Changing the model from the console.
 *
 * The settings page is otherwise server-rendered and read-only; this is the
 * one interactive island, because picking a model is a write and a write needs
 * to report what actually happened.
 *
 * The choices are not typed in — they come from the provider health probe,
 * which lists the models the endpoint really has. A free-text box invites a
 * typo that fails halfway through the next scan, hours after anyone could
 * connect the two events.
 */

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";
import type { LlmSettings, ProviderHealth } from "@/lib/api";
import { Button } from "@/components/ui";

// Say where each role is actually invoked from, not just what it would do.
// These descriptions previously read as capabilities the product had; three of
// the five had no caller at all, so an operator could configure a model, be
// told it was ready, and never see any output from it.
const ROLE_NOTES: Record<string, string> = {
  triage:
    "Runs over every candidate — thousands for a large installer. Pick for speed. " +
    'Triggered by "Run AI triage" on a run.',
  discover:
    "One call per run over unmatched strings, proposing new rules. Pick for speed. " +
    "Triggered by the discover endpoint.",
  explain:
    "One call per finding, on request. Pick for quality — it is routed to a " +
    'reasoning model by default. Triggered by "Explain this finding" on a finding.',
  investigate:
    "A loop of calls per finding, on request — the model uses tools on the " +
    "artifact. Pick for speed: a reasoning model deliberates on every turn, " +
    'and there are up to twelve. Triggered by "Investigate with AI".',
  summarize:
    'One call per run. Pick for quality. Triggered by "Write summary" at the top ' +
    "of a run.",
  remediate:
    "Not yet wired to anything. Configuring it has no effect today; the " +
    "remediation shown on a finding comes from the rule pack.",
};

export function LlmControls({ settings }: { settings: LlmSettings }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  // Reachable, not enumerable. Only the Ollama adapter can list what an
  // endpoint has; a health-probed LiteLLM provider reports an empty
  // available_models because there is no uniform model listing across its
  // vendors — not because it is unreachable. Filtering on the list used to
  // hide every provider the wizard had just connected and verified, which
  // read as "No reachable provider" until something happened to make the
  // probe report models again.
  const usable = settings.providers.filter((p) => p.healthy);

  async function send(body: Record<string, unknown>, note: string) {
    setError(null);
    setSaved(null);
    try {
      const response = await fetch("/api/settings/llm", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const detail = (await response.json().catch(() => ({}))) as { detail?: string };
        throw new Error(detail.detail ?? `HTTP ${response.status}`);
      }
      setSaved(note);
      // Re-render the server component so every panel reflects the new config
      // rather than just this island.
      startTransition(() => router.refresh());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-md border border-critical/40 bg-critical-bg px-3.5 py-2.5">
          <p className="text-[12.5px] font-medium text-critical">Could not apply the change</p>
          <p className="mt-1 font-mono text-[11.5px] text-content-muted">{error}</p>
        </div>
      )}
      {saved && !error && (
        <div className="rounded-md border border-ok/40 bg-ok-bg px-3.5 py-2.5">
          <p className="text-[12.5px] font-medium text-ok">{saved}</p>
        </div>
      )}

      {/* The master switch. Stated in the terms that matter: what still works
          when it is off. */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface px-4 py-3.5">
        <div className="min-w-0">
          <p className="text-[13.5px] font-semibold">AI assistance</p>
          <p className="mt-0.5 text-[11.5px] leading-relaxed text-content-subtle">
            {settings.enabled
              ? "Triage and explanation are available. Findings still come only from deterministic rules."
              : "Deterministic only. This is the CI default, and every report is complete without it."}
          </p>
        </div>
        <Button
          variant={settings.enabled ? "secondary" : "primary"}
          disabled={pending}
          onClick={() =>
            send(
              { enabled: !settings.enabled },
              settings.enabled ? "AI assistance disabled." : "AI assistance enabled.",
            )
          }
        >
          {settings.enabled ? "Disable" : "Enable"}
        </Button>
      </div>

      {usable.length === 0 ? (
        settings.enabled ? (
          <div className="rounded-lg border border-border bg-surface px-4 py-5">
            <p className="text-[13px] font-medium">No reachable provider</p>
            <p className="mt-1.5 max-w-xl text-[12px] leading-relaxed text-content-subtle">
              {settings.providers.length === 0
                ? "No provider is configured yet. Add one below — it is tested " +
                  "before anything is saved."
                : "Every configured provider failed its live probe. The findings " +
                  "and verdicts below them are deterministic and unchanged; see " +
                  "each provider's detail line in the Providers panel."}
            </p>
          </div>
        ) : null
      ) : (
        usable.map((provider) => (
          <ProviderCard
            key={provider.name}
            provider={provider}
            roles={settings.roles}
            pending={pending}
            onModel={(model) =>
              send(
                { provider_models: { [provider.name]: model } },
                `${provider.name} now uses ${model}.`,
              )
            }
            onRole={(role) =>
              send({ roles: { [role]: provider.name } }, `${role} now routes to ${provider.name}.`)
            }
          />
        ))
      )}
    </div>
  );
}

function ProviderCard({
  provider,
  roles,
  pending,
  onModel,
  onRole,
}: {
  provider: ProviderHealth;
  roles: Record<string, string>;
  pending: boolean;
  onModel: (model: string) => void;
  onRole: (role: string) => void;
}) {
  const assigned = Object.entries(roles)
    .filter(([, name]) => name === provider.name)
    .map(([role]) => role);

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-surface">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border px-4 py-3">
        <span className="text-[13.5px] font-semibold">{provider.name}</span>
        <span
          className={`inline-flex items-center gap-1.5 text-[11.5px] font-medium ${
            provider.healthy ? "text-ok" : "text-critical"
          }`}
        >
          <span className="h-[6px] w-[6px] rounded-full bg-current" aria-hidden />
          {provider.healthy ? "reachable" : "unreachable"}
        </span>
        {provider.is_local && (
          <span className="rounded-sm border border-ok/30 bg-ok-bg px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[0.09em] text-ok">
            on your network
          </span>
        )}
        {provider.latency_s !== null && (
          <span className="tnum ml-auto font-mono text-[11px] text-content-subtle">
            {Math.round(provider.latency_s * 1000)} ms
          </span>
        )}
      </header>

      <div className="space-y-4 px-4 py-4">
        <div>
          <p className="eyebrow">Model</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {/* Most LiteLLM vendors expose no uniform model listing, so the
                probe reports none. Show the configured model as the one chip
                rather than an empty row — the card still works for roles. */}
            {(provider.available_models.length > 0
              ? provider.available_models
              : [provider.model]
            ).map((model) => {
              const active = model === provider.model;
              return (
                <button
                  key={model}
                  type="button"
                  disabled={pending || active}
                  onClick={() => onModel(model)}
                  className={`rounded-md border px-3 py-1.5 font-mono text-[11.5px] transition-colors disabled:cursor-default ${
                    active
                      ? "border-accent bg-accent-muted text-content"
                      : "border-border bg-surface-sunken text-content-muted hover:border-content-subtle hover:text-content"
                  }`}
                >
                  {model}
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <p className="eyebrow">Roles routed here</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {Object.keys(ROLE_NOTES).map((role) => {
              const active = assigned.includes(role);
              return (
                <button
                  key={role}
                  type="button"
                  disabled={pending || active}
                  title={ROLE_NOTES[role]}
                  onClick={() => onRole(role)}
                  className={`rounded-md border px-2.5 py-1 text-[11.5px] transition-colors disabled:cursor-default ${
                    active
                      ? "border-accent bg-accent-muted text-content"
                      : "border-border bg-surface-sunken text-content-subtle hover:border-content-subtle hover:text-content"
                  }`}
                >
                  {role}
                </button>
              );
            })}
          </div>
          <p className="mt-2 text-[11.5px] leading-relaxed text-content-subtle">
            Triage is the volume job and wants a fast model; explanation is
            low-volume and wants a sharp one.
          </p>
        </div>
      </div>
    </section>
  );
}
