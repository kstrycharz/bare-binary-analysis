import { api, type LlmSettings } from "@/lib/api";
import { ErrorNotice, Mono, Panel } from "@/components/ui";
import { LlmControls } from "@/components/llm-controls";
import { AddProviderPanel } from "@/components/connect-provider";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  let settings: LlmSettings | null = null;
  let error: string | null = null;

  try {
    settings = await api.llmSettings();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-content-muted">
          BARE is deterministic first. Everything below is optional — with
          no model configured, scans still run and reports are still complete.
        </p>
      </header>

      {error && <ErrorNotice title="Could not load LLM settings" detail={error} />}

      {settings && <LlmControls settings={settings} />}

      {/* Always offered, including when the wizard's model step was skipped
          and AI assistance is off: connecting a provider is how it gets
          switched on. */}
      {settings && <AddProviderPanel hasProviders={settings.providers.length > 0} />}

      {settings && (
        <>
          <Panel
            title="Trust boundary"
            description="What can leave this network, and what cannot."
          >
            <dl className="grid divide-y divide-border sm:grid-cols-3 sm:divide-x sm:divide-y-0">
              <BoundaryCard
                label="Egress policy"
                value={settings.egress}
                tone={settings.egress === "deny" ? "good" : "warn"}
              >
                {settings.egress === "deny"
                  ? "No outbound calls except to loopback and private addresses. A model on your own LAN is permitted; the public internet is not."
                  : "Cloud providers are permitted. Artifact-derived context may leave your network."}
              </BoundaryCard>
              <BoundaryCard label="Redaction" value={settings.redaction} tone="good">
                Candidates are sent as shape, entropy, rule name, masked value,
                and offsets. Secret plaintext is never sent to any provider
                during triage.
              </BoundaryCard>
              <BoundaryCard
                label="LLM layer"
                value={settings.enabled ? "enabled" : "disabled"}
                tone="neutral"
              >
                {settings.enabled
                  ? "Triage is available. It never creates findings — only classifies and explains them."
                  : "Deterministic-only. This is the CI default."}
              </BoundaryCard>
            </dl>
            {settings.config_path && (
              <p className="border-t border-border px-4 py-2">
                <Mono className="text-content-subtle">{settings.config_path}</Mono>
              </p>
            )}
          </Panel>

          <Panel
            title="Role routing"
            description="Triage runs over every candidate and needs a small, fast, non-reasoning model. Explanation runs over a handful of confirmed findings and can afford a large one."
          >
            <table className="w-full text-sm">
              <tbody>
                {Object.entries(settings.roles).map(([role, provider]) => (
                  <tr key={role} className="border-b border-border/60 last:border-0">
                    <td className="px-4 py-1.5 font-mono text-xs text-content-muted">{role}</td>
                    <td className="px-4 py-1.5 font-mono text-xs">{provider}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>

          <Panel
            title="Providers"
            description="Probed live on page load — a stale green tick is worse than none."
          >
            <ul>
              {settings.providers.map((provider) => (
                <li
                  key={provider.name}
                  className="border-b border-border/60 px-4 py-3 last:border-0"
                >
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        provider.healthy ? "bg-ok" : "bg-critical"
                      }`}
                      aria-hidden
                    />
                    <span className="text-sm font-medium">{provider.name}</span>
                    <Mono className="rounded bg-surface-sunken px-1.5 py-px">
                      {provider.model}
                    </Mono>
                    <span
                      className={`rounded px-1.5 py-px text-[10px] font-medium uppercase tracking-wider ${
                        provider.is_local
                          ? "bg-ok-bg text-ok"
                          : "bg-medium-bg text-medium"
                      }`}
                    >
                      {provider.is_local ? "local" : "remote"}
                    </span>
                    {provider.latency_s !== null && (
                      <span className="text-xs text-content-subtle tnum">
                        {(provider.latency_s * 1000).toFixed(0)}ms
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-content-muted">{provider.detail}</p>
                  {provider.available_models.length > 0 && (
                    <p className="mt-1 truncate text-[11px] text-content-subtle">
                      <Mono>{provider.available_models.join("  ·  ")}</Mono>
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </Panel>
        </>
      )}
    </div>
  );
}

function BoundaryCard({
  label,
  value,
  tone,
  children,
}: {
  label: string;
  value: string;
  tone: "good" | "warn" | "neutral";
  children: React.ReactNode;
}) {
  const valueClass =
    tone === "good" ? "text-ok" : tone === "warn" ? "text-medium" : "text-content";
  return (
    <div className="px-4 py-3">
      <dt className="text-[11px] font-medium uppercase tracking-wider text-content-subtle">
        {label}
      </dt>
      <dd className={`mt-0.5 text-sm font-semibold ${valueClass}`}>{value}</dd>
      <p className="mt-1 text-xs text-content-muted">{children}</p>
    </div>
  );
}
