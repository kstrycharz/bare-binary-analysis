/**
 * Release posture — the console's home.
 *
 * Server-rendered with no client JavaScript: §4 requires the dashboard to
 * render usefully with JS disabled, and every graphic here is inline SVG.
 *
 * Structurally this is a command centre, not a card grid. The verdict for the
 * most recent build occupies the fold at a size meant to be read across a
 * room, the fleet numbers sit on one rule beneath it, and everything else is
 * the run log. A dashboard whose most urgent fact is the same size as its
 * least urgent one makes the reader do the triage, which is the job the
 * product is supposed to have done already.
 */

import Link from "next/link";
import { api, type RunSummary, type Severity } from "@/lib/api";
import { Button, SeverityBar, bytes, relativeTime } from "@/components/ui";
import { RunsLive } from "@/components/runs-live";

export const dynamic = "force-dynamic";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  info: "text-info",
};

function sumCounts(runs: RunSummary[]): Partial<Record<Severity, number>> {
  const totals: Partial<Record<Severity, number>> = {};
  for (const run of runs) {
    for (const [severity, count] of Object.entries(run.severity_counts)) {
      const key = severity as Severity;
      totals[key] = (totals[key] ?? 0) + count;
    }
  }
  return totals;
}

/**
 * The most recent completed run per artifact.
 *
 * Fleet totals must not sum every run ever recorded. Re-scanning an artifact —
 * after a fix, or after a rule-pack change — would otherwise count it twice and
 * keep superseded findings in the posture forever. "Where do we stand" is a
 * question about current builds, and the answer is the latest run of each.
 *
 * The runs list is newest-first, so the first sighting of a name wins.
 */
function latestPerArtifact(runs: RunSummary[]): RunSummary[] {
  const seen = new Set<string>();
  const current: RunSummary[] = [];
  for (const run of runs) {
    const key = run.artifact_name ?? run.id;
    if (seen.has(key)) continue;
    seen.add(key);
    current.push(run);
  }
  return current;
}

export default async function OverviewPage() {
  let runs: RunSummary[] = [];
  let error: string | null = null;

  try {
    runs = await api.listRuns();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const completed = runs.filter((r) => r.status === "completed");
  const current = latestPerArtifact(completed);
  const latest = completed[0];
  const latestCounts = latest?.severity_counts ?? {};
  const blocking = (latestCounts.critical ?? 0) + (latestCounts.high ?? 0);

  const fleetCounts = sumCounts(current);
  const fleetBlocking = (fleetCounts.critical ?? 0) + (fleetCounts.high ?? 0);
  const fleetTotal = Object.values(fleetCounts).reduce((a, b) => a + b, 0);
  const filesAnalysed = current.reduce((sum, r) => sum + (r.artifact_count ?? 1), 0);
  const newThisBuild = completed.reduce((sum, r) => sum + (r.new_since_previous ?? 0), 0);
  const degraded = runs.filter((r) => r.status === "failed").length;

  return (
    <div className="space-y-7">
      <RunsLive>
        <div className="space-y-7">
          {error && (
            <div className="rounded-lg border border-critical/40 bg-critical-bg px-5 py-4">
              <p className="text-[13px] font-semibold text-critical">API unreachable</p>
              <p className="mt-1 break-words font-mono text-[11.5px] text-content-muted">{error}</p>
            </div>
          )}

          {!error && runs.length === 0 && <FirstRun />}

          {latest && (
            <>
              {/* The fold. One verdict, at a size that carries. */}
              <Verdict run={latest} blocking={blocking} counts={latestCounts} />

              {/* Fleet numbers on a single rule — a row of equals, because none of
                  them outranks another. */}
              <section className="surface-panel grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
                <Stat
                  label="Would block a release"
                  value={fleetBlocking}
                  tone={fleetBlocking > 0 ? "critical" : "ok"}
                  hint={`across ${current.length} artifact${current.length === 1 ? "" : "s"}`}
                />
                <Stat
                  label="Introduced by a build"
                  value={newThisBuild}
                  tone={newThisBuild > 0 ? "high" : "ok"}
                  hint="what the gate fails on"
                />
                <Stat label="Open findings" value={fleetTotal} hint="current build of each" />
                <Stat
                  label="Files analysed"
                  value={filesAnalysed}
                  hint={degraded > 0 ? `${degraded} run(s) failed` : "unpacked recursively"}
                  tone={degraded > 0 ? "high" : "neutral"}
                />
              </section>

              <RunLog runs={runs} />
            </>
          )}
        </div>
      </RunsLive>
    </div>
  );
}

/* ------------------------------------------------------------------ verdict */

function Verdict({
  run,
  blocking,
  counts,
}: {
  run: RunSummary;
  blocking: number;
  counts: Partial<Record<Severity, number>>;
}) {
  const blocked = blocking > 0;

  return (
    <section className="surface-hero overflow-hidden rounded-xl border border-border bg-surface">
      <div className="flex flex-col gap-8 p-7 lg:flex-row lg:items-center lg:gap-12 lg:p-9">
        <div className="min-w-0 lg:w-[380px] lg:shrink-0">
          <div className="flex items-center gap-2.5">
            <span
              className={`h-2 w-2 rounded-full ${blocked ? "bg-critical" : "bg-ok"}`}
              aria-hidden
            />
            <span
              className={`text-[10.5px] font-semibold uppercase tracking-[0.14em] ${
                blocked ? "text-critical" : "text-ok"
              }`}
            >
              Latest build
            </span>
          </div>

          <p
            className={`figure mt-4 text-[64px] lg:text-[76px] ${
              blocked ? "text-critical" : "text-ok"
            }`}
          >
            {blocked ? "BLOCKED" : "CLEAR"}
          </p>

          <p className="mt-4 max-w-[34ch] text-[14px] leading-relaxed text-content-muted text-pretty">
            {blocked
              ? `${blocking} finding${blocking === 1 ? "" : "s"} at critical or high. A release gated on severity stops here.`
              : "Nothing at critical or high. A release gated on severity clears this build."}
          </p>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Link href={`/runs/${run.id}`}>
              <Button variant="primary">Inspect run</Button>
            </Link>
            <Link href="/scan">
              <Button variant="secondary">New scan</Button>
            </Link>
          </div>
        </div>

        {/* What the verdict is made of. */}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
            <p className="min-w-0 truncate text-[17px] font-semibold tracking-[-0.014em]">
              {run.artifact_name ?? run.id.slice(0, 12)}
            </p>
            <p className="tnum font-mono text-[11.5px] text-content-subtle">
              {run.artifact_sha256?.slice(0, 16) ?? "—"} · {bytes(run.artifact_size_bytes)} ·{" "}
              {relativeTime(run.finished_at ?? run.created_at)}
            </p>
          </div>

          <div className="mt-6 space-y-2.5">
            {SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((severity) => (
              <SeverityRow
                key={severity}
                severity={severity}
                count={counts[severity] ?? 0}
                total={run.finding_count || 1}
              />
            ))}
            {run.finding_count === 0 && (
              <p className="text-[13px] text-content-subtle">
                No findings. Every rule in the pack was evaluated against this artifact.
              </p>
            )}
          </div>

          <p className="mt-6 border-t border-border pt-4 text-[11.5px] leading-relaxed text-content-subtle text-pretty">
            {run.new_since_previous === null
              ? "Baseline run — nothing to compare against yet, so every finding counts as new."
              : run.new_since_previous === 0
                ? "Nothing new since the previous run of this artifact. Inherited findings are reported but do not block."
                : `${run.new_since_previous} finding${run.new_since_previous === 1 ? "" : "s"} introduced by this build. The gate fails on these, not on what was inherited.`}
          </p>
        </div>
      </div>
    </section>
  );
}

/** One severity, as a proportional bar. Reads as a distribution at a glance
 *  without the reader decoding a legend. */
function SeverityRow({
  severity,
  count,
  total,
}: {
  severity: Severity;
  count: number;
  total: number;
}) {
  const pct = Math.max(2, Math.round((count / total) * 100));
  return (
    <div className="flex items-center gap-3">
      <span
        className={`w-[68px] shrink-0 text-[10px] font-semibold uppercase tracking-[0.1em] ${SEVERITY_TEXT[severity]}`}
      >
        {severity}
      </span>
      <div className="h-[7px] min-w-0 flex-1 overflow-hidden rounded-full bg-surface-inset">
        <div
          className={`h-full rounded-full ${SEVERITY_TEXT[severity]}`}
          style={{ width: `${pct}%`, background: "currentColor" }}
        />
      </div>
      <span className={`tnum w-9 shrink-0 text-right text-[14px] font-semibold ${SEVERITY_TEXT[severity]}`}>
        {count}
      </span>
    </div>
  );
}

/* -------------------------------------------------------------------- stats */

function Stat({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: number;
  hint: string;
  tone?: "neutral" | "ok" | "high" | "critical";
}) {
  const toneClass = {
    neutral: "text-content",
    ok: "text-ok",
    high: "text-high",
    critical: "text-critical",
  }[tone];

  return (
    <div className="bg-surface px-5 py-4">
      <p className="eyebrow">{label}</p>
      <p className={`figure mt-2.5 text-[32px] ${toneClass}`}>{value.toLocaleString()}</p>
      <p className="mt-1.5 text-[11.5px] text-content-subtle">{hint}</p>
    </div>
  );
}

/* ------------------------------------------------------------------ run log */

function RunLog({ runs }: { runs: RunSummary[] }) {
  return (
    <section className="surface-panel overflow-hidden rounded-lg border border-border bg-surface">
      <header className="flex items-center justify-between border-b border-border px-5 py-3.5">
        <h2 className="text-[13.5px] font-semibold tracking-[-0.008em]">Runs</h2>
        <span className="tnum text-[11.5px] text-content-subtle">{runs.length} total</span>
      </header>

      <div className="scroll-x">
        <table className="w-full min-w-[860px] border-collapse">
          <thead>
            <tr className="border-b border-border">
              {["Artifact", "Status", "Findings", "Delta", "Files", "Started"].map((h, i) => (
                <th
                  key={h}
                  className={`eyebrow px-5 py-2.5 font-semibold ${
                    i > 2 ? "text-right" : "text-left"
                  }`}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <RunRow key={run.id} run={run} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function RunRow({ run }: { run: RunSummary }) {
  const blocking =
    (run.severity_counts.critical ?? 0) + (run.severity_counts.high ?? 0);
  const live = run.status === "running" || run.status === "queued";

  const statusTone =
    run.status === "completed"
      ? "text-ok"
      : run.status === "failed"
        ? "text-critical"
        : live
          ? "text-accent"
          : "text-content-subtle";

  return (
    <tr className="group border-b hairline last:border-0 transition-colors hover:bg-surface-raised">
      {/* A severity rail rather than a coloured row: the eye finds the
          blocking builds down the left edge without the table turning red. */}
      <td className="relative px-5 py-3">
        <span
          aria-hidden
          className={`absolute left-0 top-0 h-full w-[2px] ${
            blocking > 0 ? "bg-critical" : "bg-transparent"
          }`}
        />
        <Link href={`/runs/${run.id}`} className="block min-w-0">
          <span className="block truncate text-[13px] font-medium group-hover:text-accent">
            {run.artifact_name ?? run.id.slice(0, 12)}
          </span>
          <span className="tnum mt-0.5 block font-mono text-[10.5px] text-content-subtle">
            {run.artifact_sha256?.slice(0, 12) ?? run.id.slice(0, 12)} ·{" "}
            {bytes(run.artifact_size_bytes)}
          </span>
        </Link>
      </td>

      <td className="px-5 py-3">
        <span className={`inline-flex items-center gap-2 text-[12px] font-medium ${statusTone}`}>
          <span className="relative flex h-[7px] w-[7px]" aria-hidden>
            {live && (
              <span className="sg-pulse absolute inline-flex h-full w-full rounded-full bg-current opacity-60" />
            )}
            <span className="relative inline-flex h-[7px] w-[7px] rounded-full bg-current" />
          </span>
          {run.status}
        </span>
      </td>

      <td className="px-5 py-3">
        {run.finding_count > 0 ? (
          <SeverityBar counts={run.severity_counts} />
        ) : run.status === "completed" ? (
          <span className="text-[12px] text-ok">clean</span>
        ) : (
          <span className="text-[12px] text-content-subtle">—</span>
        )}
      </td>

      <td className="tnum px-5 py-3 text-right text-[12px]">
        {run.new_since_previous === null ? (
          <span className="text-content-subtle">baseline</span>
        ) : run.new_since_previous === 0 ? (
          <span className="text-content-subtle">no change</span>
        ) : (
          <span className="text-high">+{run.new_since_previous}</span>
        )}
      </td>

      <td className="tnum px-5 py-3 text-right text-[12px] text-content-muted">
        {(run.artifact_count ?? 1).toLocaleString()}
      </td>

      <td className="tnum px-5 py-3 text-right text-[12px] text-content-subtle">
        {relativeTime(run.started_at ?? run.created_at)}
      </td>
    </tr>
  );
}

/* ------------------------------------------------------------------- empty */

function FirstRun() {
  return (
    <section className="surface-panel rounded-xl border border-border bg-surface px-8 py-14 text-center">
      <p className="text-[17px] font-semibold">No scans yet</p>
      <p className="mx-auto mt-2.5 max-w-lg text-[13.5px] leading-relaxed text-content-muted text-pretty">
        Upload an installer, executable, archive, or firmware image. BARE
        unpacks it recursively and reports the secrets, internal hostnames, and
        build metadata baked into what you are about to ship.
      </p>
      <div className="mt-6 flex justify-center">
        <Link href="/scan">
          <Button variant="primary">Scan an artifact</Button>
        </Link>
      </div>
    </section>
  );
}
