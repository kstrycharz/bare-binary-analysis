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
 *
 * Skipping must not be a one-way door. The provider form is shared with the
 * Settings page (`ConnectProvider`), and this page opens straight on the model
 * step once a token already exists, rather than offering to mint a token that
 * the API will refuse.
 */

import { useEffect, useState } from "react";
import { Button, ErrorNotice, Panel } from "@/components/ui";
import { ConnectProvider } from "@/components/connect-provider";

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
  const [step, setStep] = useState<"checking" | "token" | "model">("checking");

  useEffect(() => {
    // Only a deployment that has already minted its token skips step one. If
    // the answer is unavailable, show step one: it handles an existing token
    // itself (the bootstrap call returns 409 and moves on).
    fetch("/api/setup/status", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : { needs_setup: true }))
      .then((body: { needs_setup?: boolean }) =>
        setStep(body.needs_setup === false ? "model" : "token"),
      )
      .catch(() => setStep("token"));
  }, []);

  if (step === "checking") return null;
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
  const [connected, setConnected] = useState<string | null>(null);

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
      <ConnectProvider
        actions={<Button onClick={leaveSetup}>Skip for now</Button>}
        onConnected={setConnected}
      />
      <p className="mt-3 text-[11.5px] leading-relaxed text-content-subtle">
        Skipping is fine — you can add a provider at any time from Settings.
      </p>
    </Shell>
  );
}
