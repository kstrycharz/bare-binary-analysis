"use client";

/**
 * Findings explorer.
 *
 * A dense, keyboard-navigable table — AppSec engineers work through these
 * lists for hours, and a card layout that shows eight findings per screen is a
 * worse tool than a table that shows forty.
 *
 * The "deterministic only" toggle is the control that matters (§2.5). With it
 * on, every AI-derived field disappears and what remains is exactly what the
 * scanner produces with no model configured. A user must always be able to
 * answer "would this finding exist without the AI?", and the honest way to
 * answer it is to show them.
 */

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import type {
  ExplainResponse,
  Finding,
  InvestigateResponse,
  Severity,
  TriageResponse,
} from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/severity";
import { Button, Mono, Panel, SeverityTag, duration, relativeTime } from "@/components/ui";

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  confirmed: "Confirmed",
  needs_review: "Needs review",
  false_positive: "False positive",
  accepted_risk: "Accepted",
  fixed: "Fixed",
};

const STATUS_STYLE: Record<string, string> = {
  confirmed: "text-critical",
  needs_review: "text-high",
  false_positive: "text-content-subtle line-through",
  accepted_risk: "text-content-subtle",
  fixed: "text-ok",
  open: "text-content-muted",
};

export function FindingsExplorer({
  runId,
  initialFindings,
  llmEnabled,
}: {
  runId: string;
  initialFindings: Finding[];
  llmEnabled: boolean;
}) {
  const [findings, setFindings] = useState(initialFindings);
  const [deterministicOnly, setDeterministicOnly] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [newOnly, setNewOnly] = useState(false);
  const [hideDismissed, setHideDismissed] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [triaging, setTriaging] = useState(false);
  const [triageResult, setTriageResult] = useState<TriageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (severityFilter.size > 0 && !severityFilter.has(f.severity)) return false;
      if (newOnly && !f.is_new) return false;
      if (hideDismissed && f.status === "false_positive") return false;
      if (needle) {
        const haystack = `${f.title} ${f.rule_id} ${f.category} ${f.value_masked} ${f.locations
          .map((l) => l.path_in_tree)
          .join(" ")}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [findings, severityFilter, newOnly, hideDismissed, query]);

  const counts = useMemo(() => {
    const result: Partial<Record<Severity, number>> = {};
    for (const f of findings) result[f.severity] = (result[f.severity] ?? 0) + 1;
    return result;
  }, [findings]);

  const setStatus = useCallback(
    async (finding: Finding, status: string) => {
      const response = await fetch(`/api/runs/${runId}/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (response.ok) {
        const updated = (await response.json()) as Finding;
        setFindings((current) => current.map((f) => (f.id === updated.id ? updated : f)));
      }
    },
    [runId],
  );

  // Keyboard navigation. AppSec engineers live in j/k/x/e; making them reach
  // for the mouse on every row is the difference between a tool they use and
  // one they export to a spreadsheet.
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA") return;

      const current = visible[cursor];
      if (event.key === "j" || event.key === "ArrowDown") {
        event.preventDefault();
        setCursor((c) => Math.min(c + 1, visible.length - 1));
      } else if (event.key === "k" || event.key === "ArrowUp") {
        event.preventDefault();
        setCursor((c) => Math.max(c - 1, 0));
      } else if (event.key === "Enter" || event.key === "e") {
        if (current) setExpanded((x) => (x === current.id ? null : current.id));
      } else if (event.key === "x" && current) {
        void setStatus(current, "false_positive");
      } else if (event.key === "c" && current) {
        void setStatus(current, "confirmed");
      } else if (event.key === "d") {
        setDeterministicOnly((v) => !v);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visible, cursor, setStatus]);

  function toggleSeverity(severity: Severity) {
    const next = new Set(severityFilter);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    setSeverityFilter(next);
    setCursor(0);
  }

  async function runTriage() {
    setTriaging(true);
    setError(null);
    try {
      const response = await fetch(`/api/runs/${runId}/triage`, { method: "POST" });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { detail?: string };
        throw new Error(body.detail ?? response.statusText);
      }
      setTriageResult((await response.json()) as TriageResponse);
      const refreshed = await fetch(`/api/runs/${runId}/findings`);
      setFindings((await refreshed.json()) as Finding[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setTriaging(false);
    }
  }

  return (
    <Panel
      title={`Findings (${visible.length}${visible.length !== findings.length ? ` of ${findings.length}` : ""})`}
      actions={
        <>
          <label
            className="flex cursor-pointer items-center gap-1.5 text-xs text-content-muted"
            title="Hide every AI-derived field. What remains is exactly what the scanner produces with no model configured. (d)"
          >
            <input
              type="checkbox"
              checked={deterministicOnly}
              onChange={(e) => setDeterministicOnly(e.target.checked)}
            />
            Deterministic only
          </label>
          {llmEnabled && !deterministicOnly && (
            <Button onClick={runTriage} disabled={triaging || findings.length === 0}>
              {triaging ? "Triaging…" : "Run AI triage"}
            </Button>
          )}
        </>
      }
    >
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-border px-4 py-2.5">
        <input
          type="search"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setCursor(0);
          }}
          placeholder="Filter by rule, value, or path…"
          className="w-56 rounded-md border border-border bg-surface px-2.5 py-1 text-sm placeholder:text-content-subtle"
        />

        <div className="flex flex-wrap items-center gap-1">
          {SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((severity) => {
            const active = severityFilter.has(severity);
            return (
              <button
                key={severity}
                type="button"
                onClick={() => toggleSeverity(severity)}
                aria-pressed={active}
                className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] transition-all ${
                  active
                    ? "border-content-muted"
                    : "border-transparent opacity-55 hover:opacity-100"
                }`}
              >
                <SeverityTag severity={severity} size="xs" />
                <span className="tnum">{counts[severity]}</span>
              </button>
            );
          })}
        </div>

        <label className="flex items-center gap-1.5 text-xs text-content-muted">
          <input type="checkbox" checked={newOnly} onChange={(e) => setNewOnly(e.target.checked)} />
          New only
        </label>
        <label className="flex items-center gap-1.5 text-xs text-content-muted">
          <input
            type="checkbox"
            checked={hideDismissed}
            onChange={(e) => setHideDismissed(e.target.checked)}
          />
          Hide dismissed
        </label>

        <span className="ml-auto text-[11px] text-content-subtle">
          <kbd className="rounded border border-border px-1">j</kbd>
          <kbd className="ml-0.5 rounded border border-border px-1">k</kbd> move ·{" "}
          <kbd className="rounded border border-border px-1">e</kbd> expand ·{" "}
          <kbd className="rounded border border-border px-1">c</kbd> confirm ·{" "}
          <kbd className="rounded border border-border px-1">x</kbd> dismiss
        </span>
      </div>

      {deterministicOnly && (
        <p className="border-b border-border bg-surface-sunken px-4 py-1.5 text-xs text-content-muted">
          Rule output only. Every finding below exists with no model involvement.
        </p>
      )}

      {triageResult && !deterministicOnly && (
        <p className="border-b border-border bg-surface-sunken px-4 py-1.5 text-xs text-content-muted">
          <Mono>{triageResult.model}</Mono> triaged {triageResult.triaged} in{" "}
          {duration(triageResult.duration_s)} — {triageResult.confirmed} confirmed,{" "}
          {triageResult.dismissed} dismissed, {triageResult.needs_review} need review
          {triageResult.errors > 0 && `, ${triageResult.errors} errored`}. Severities
          and offsets are unchanged.
        </p>
      )}

      {error && (
        <p className="border-b border-border bg-critical-bg px-4 py-2 text-sm text-critical">
          {error}
        </p>
      )}

      {visible.length === 0 ? (
        <p className="px-4 py-10 text-center text-sm text-content-muted">
          {findings.length === 0
            ? "No findings. Check the stage list above — a degraded analyzer is not the same as a clean artifact."
            : "No findings match these filters."}
        </p>
      ) : (
        <div className="scroll-x">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-content-subtle">
                <th scope="col" className="px-4 py-1.5 font-medium">Severity</th>
                <th scope="col" className="px-2 py-1.5 font-medium">Finding</th>
                <th scope="col" className="px-2 py-1.5 font-medium">Value</th>
                <th scope="col" className="px-2 py-1.5 font-medium">Location</th>
                <th scope="col" className="px-2 py-1.5 font-medium">Status</th>
                {!deterministicOnly && (
                  <th scope="col" className="px-2 py-1.5 font-medium">AI</th>
                )}
              </tr>
            </thead>
            <tbody>
              {visible.map((finding, index) => {
                const open = expanded === finding.id;
                const primary = finding.locations[0];
                return (
                  // The key belongs on the fragment: it is the list item. A key
                  // on the <tr> inside a bare <> does not count.
                  <Fragment key={finding.id}>
                    <tr
                      onClick={() => {
                        setCursor(index);
                        setExpanded(open ? null : finding.id);
                      }}
                      className={`cursor-pointer border-b border-border/60 ${
                        index === cursor ? "bg-accent-muted/60" : "hover:bg-surface-sunken/60"
                      }`}
                    >
                      <td className="px-4 py-1.5">
                        <SeverityTag severity={finding.severity} size="xs" />
                      </td>
                      <td className="px-2 py-1.5">
                        <span className="font-medium">{finding.title}</span>
                        {finding.is_new && (
                          <span className="ml-1.5 rounded bg-high-bg px-1 py-px text-[10px] font-medium text-high">
                            NEW
                          </span>
                        )}
                        {finding.location_count > 1 && (
                          <span className="ml-1.5 text-[11px] text-content-subtle">
                            ×{finding.location_count}
                          </span>
                        )}
                      </td>
                      <td className="px-2 py-1.5">
                        <Mono className="text-content-muted">{finding.value_masked}</Mono>
                      </td>
                      <td className="max-w-[22rem] px-2 py-1.5">
                        <div
                          className="truncate font-mono text-xs text-content-subtle"
                          title={primary?.path_in_tree}
                        >
                          {primary?.path_in_tree ?? "—"}
                          {primary?.offset != null && (
                            <span className="ml-1">@0x{primary.offset.toString(16)}</span>
                          )}
                          {primary?.encoding === "utf-16le" && (
                            <span className="ml-1 rounded bg-surface-sunken px-1">w</span>
                          )}
                        </div>
                      </td>
                      <td className={`px-2 py-1.5 text-xs ${STATUS_STYLE[finding.status] ?? ""}`}>
                        {STATUS_LABEL[finding.status] ?? finding.status}
                      </td>
                      {!deterministicOnly && (
                        <td className="px-2 py-1.5 text-xs">
                          {finding.llm ? (
                            <span className="text-accent">
                              {finding.llm.verdict.replace(/_/g, " ")}
                            </span>
                          ) : (
                            <span className="text-content-subtle">—</span>
                          )}
                        </td>
                      )}
                    </tr>

                    {open && (
                      <tr className="border-b border-border">
                        <td colSpan={deterministicOnly ? 5 : 6} className="bg-surface-sunken px-4 py-4">
                          <FindingDetail
                            finding={finding}
                            deterministicOnly={deterministicOnly}
                            onStatus={(status) => setStatus(finding, status)}
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function FindingDetail({
  finding,
  deterministicOnly,
  onStatus,
}: {
  finding: Finding;
  deterministicOnly: boolean;
  onStatus: (status: string) => void;
}) {
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <div className="space-y-4 lg:col-span-2">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-4">
          <Field label="Rule" value={<Mono>{finding.rule_id}</Mono>} />
          <Field label="Category" value={finding.category} />
          <Field label="Entropy" value={finding.entropy?.toFixed(2) ?? "—"} />
          <Field label="CWE" value={finding.cwe ?? "—"} />
          <Field label="Confidence" value={finding.confidence.toFixed(2)} />
          <Field
            label="Detected by"
            value={deterministicOnly ? "rule" : finding.detected_by}
          />
          <Field label="ID" value={<Mono>{finding.id.slice(0, 16)}</Mono>} />
        </dl>

        <SecretValue finding={finding} />

        <div>
          <Label>All {finding.locations.length} location(s)</Label>
          <ul className="mt-1 space-y-0.5">
            {finding.locations.map((location, index) => (
              <li key={index} className="font-mono text-xs">
                <span className="text-content">{location.path_in_tree}</span>
                {location.offset != null && (
                  <span className="ml-1.5 text-content-subtle">
                    0x{location.offset.toString(16)}
                  </span>
                )}
                {location.encoding && (
                  <span className="ml-1.5 rounded bg-surface px-1 text-[10px] text-content-subtle">
                    {location.encoding}
                  </span>
                )}
                {location.xref_function && (
                  <span
                    className="ml-1.5 text-content-subtle"
                    title="The function that references this string, as named by Ghidra"
                  >
                    in <span className="text-content">{location.xref_function}()</span>
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>

        {finding.context_snippet && <ContextSnippet finding={finding} />}

        {!deterministicOnly && finding.llm && (
          <div className="rounded border border-accent/30 bg-accent-muted/40 p-3">
            <Label>AI triage — advisory</Label>
            <p className="mt-1 text-sm">{finding.llm.reasoning}</p>
            <p className="mt-2 text-xs text-content-muted">
              Verdict <strong>{finding.llm.verdict.replace(/_/g, " ")}</strong> from{" "}
              <Mono>{finding.llm.model}</Mono>
              {finding.llm.assessed_at && ` · ${relativeTime(finding.llm.assessed_at)}`}. The
              finding, its severity, and its offsets come from the rule and are
              unchanged by this.
            </p>
          </div>
        )}

        {!deterministicOnly && <Explanation finding={finding} />}

        {!deterministicOnly && <DeepInvestigation finding={finding} />}
      </div>

      <div className="space-y-4">
        {finding.remediation_md && (
          <div>
            <Label>Remediation</Label>
            <pre className="mt-1 whitespace-pre-wrap font-sans text-sm text-content-muted">
              {finding.remediation_md}
            </pre>
          </div>
        )}

        <div>
          <Label>Triage</Label>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {["confirmed", "false_positive", "accepted_risk", "fixed"].map((status) => (
              <Button
                key={status}
                onClick={(e) => {
                  e.stopPropagation();
                  onStatus(status);
                }}
                disabled={finding.status === status}
                className="!px-2 !py-1 !text-xs"
              >
                {STATUS_LABEL[status]}
              </Button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * The `investigate` role: the model uses tools on the artifact and reports.
 *
 * The transcript is collapsed but present, and that is the point rather than a
 * detail. An investigation is the one AI output here that makes claims the
 * scanner did not — so every claim has to be checkable against the tool call
 * that produced it. A conclusion with nothing behind it is one to distrust,
 * and the reader can only notice that if the steps are there to look at.
 */
function DeepInvestigation({ finding }: { finding: Finding }) {
  const [conclusion, setConclusion] = useState(finding.llm_investigation);
  const [confidence, setConfidence] = useState(finding.llm_investigation_confidence);
  const [steps, setSteps] = useState(finding.llm_investigation_steps ?? []);
  const [model, setModel] = useState(finding.llm_investigated_by);
  const [at, setAt] = useState(finding.llm_investigated_at);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/runs/${finding.run_id}/findings/${finding.id}/investigate`,
        { method: "POST" },
      );
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? `investigation failed (HTTP ${response.status})`);
      }
      const result = body as InvestigateResponse;
      setConclusion(result.conclusion);
      setConfidence(result.confidence);
      setModel(result.model);
      setAt(new Date().toISOString());
      // The response carries a count; the steps themselves arrive with the
      // next fetch of the finding.
      setSteps([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!conclusion) {
    return (
      <div>
        <Button
          onClick={(e) => {
            e.stopPropagation();
            void run();
          }}
          disabled={busy}
        >
          {busy ? "Investigating…" : "Investigate with AI"}
        </Button>
        <p className="mt-1 text-[11px] text-content-subtle">
          The model reads bytes, decodes values, and searches this run for
          related strings, then reports what it found. Slower than an
          explanation — it is several calls, not one.
        </p>
        {error && <p className="mt-1.5 text-xs text-critical">{error}</p>}
      </div>
    );
  }

  return (
    <div className="rounded border border-accent/30 bg-accent-muted/40 p-3">
      <Label>AI investigation — advisory</Label>
      <p className="mt-1 whitespace-pre-wrap text-sm">{conclusion}</p>

      {steps.length > 0 && (
        <div className="mt-2">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setOpen((on) => !on);
            }}
            className="text-xs text-content-muted underline hover:text-content"
          >
            {open ? "Hide" : "Show"} the {steps.length} step
            {steps.length === 1 ? "" : "s"} behind this
          </button>
          {open && (
            <ol className="mt-1.5 space-y-1.5">
              {steps.map((step, index) => (
                <li key={index} className="rounded border border-border bg-surface p-2">
                  <div className="flex items-center gap-1.5">
                    <Mono className="text-[11px]">{step.tool}</Mono>
                    {!step.ok && (
                      <span className="rounded bg-critical-bg px-1 text-[9.5px] uppercase tracking-wider text-critical">
                        failed
                      </span>
                    )}
                  </div>
                  <pre className="scroll-x mt-1 whitespace-pre-wrap font-mono text-[10.5px] text-content-muted">
                    {step.ok ? step.output : step.detail}
                  </pre>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}

      <p className="mt-2 text-xs text-content-muted">
        {confidence && (
          <>
            Confidence <strong>{confidence}</strong>.{" "}
          </>
        )}
        Investigated by <Mono>{model ?? "an AI model"}</Mono>
        {at && ` · ${relativeTime(at)}`}. Advisory: it cannot create a finding,
        or change this one&apos;s severity or location.
      </p>
      {error && <p className="mt-1.5 text-xs text-critical">{error}</p>}
    </div>
  );
}

/**
 * The `explain` role, on demand.
 *
 * On demand rather than automatic because this role is routed to a reasoning
 * model by default, which costs tens of seconds per call — running it over
 * every finding in a run would take longer than the scan that produced them.
 *
 * The panel names the role, the model, and when it ran, because the previous
 * arrangement (a single unlabelled "AI assessment" box) left no way to tell
 * which model said what, or whether what you were reading was a triage
 * verdict or an explanation.
 */
function Explanation({ finding }: { finding: Finding }) {
  const [text, setText] = useState(finding.llm_explanation);
  const [model, setModel] = useState(finding.llm_explained_by);
  const [at, setAt] = useState(finding.llm_explained_at);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      // A bare fetch through the proxy route, not `lib/api`: that module is
      // server-only (it reads the dashboard's token from disk) and importing
      // it here pulls `node:fs` into the browser bundle, which fails the
      // build. Client components authenticate by going through the proxy,
      // which attaches the token server-side.
      const response = await fetch(
        `/api/runs/${finding.run_id}/findings/${finding.id}/explain`,
        { method: "POST" },
      );
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? `explain failed (HTTP ${response.status})`);
      }
      const result = body as ExplainResponse;
      setText(result.explanation);
      setModel(result.model);
      setAt(new Date().toISOString());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!text) {
    return (
      <div>
        <Button
          onClick={(e) => {
            e.stopPropagation();
            void run();
          }}
          disabled={busy}
        >
          {busy ? "Explaining…" : "Explain this finding with AI"}
        </Button>
        {error && (
          <p className="mt-1.5 text-xs text-critical">{error}</p>
        )}
      </div>
    );
  }

  return (
    <div className="rounded border border-accent/30 bg-accent-muted/40 p-3">
      <Label>AI explanation — advisory</Label>
      <p className="mt-1 whitespace-pre-wrap text-sm">{text}</p>
      <p className="mt-2 text-xs text-content-muted">
        Written by <Mono>{model ?? "an AI model"}</Mono>
        {at && ` · ${relativeTime(at)}`}. Advisory prose only — it cannot change
        this finding, its severity, or where it was found.
      </p>
      {error && <p className="mt-1.5 text-xs text-critical">{error}</p>}
    </div>
  );
}

/**
 * The finding's value, masked by default.
 *
 * Reveal is click-to-show, because the common way to leak a secret from a tool
 * like this is to have it already on screen when someone shares it.
 * Deliberately not gated behind the deterministic-view toggle: the plaintext
 * comes from the rule match, not from a model.
 *
 * A list rather than one value, because a clustered finding covers many —
 * "40 values, e.g. …" is one finding over 40 distinct paths, and showing only
 * the first would be the least useful one to pick.
 */
function SecretValue({ finding }: { finding: Finding }) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const values = finding.value_plaintexts ?? [];
  const has = values.length > 0;

  async function copy() {
    if (!has) return;
    await navigator.clipboard.writeText(values.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const showing = revealed && has;

  return (
    <div>
      <Label>
        Value{showing ? " — plaintext" : " — masked"}
        {has && values.length > 1 && ` (${values.length})`}
      </Label>

      <div className="mt-1 flex flex-wrap items-start gap-2">
        {showing ? (
          <div className="scroll-x max-h-64 min-w-0 flex-1 overflow-y-auto rounded border border-critical/40 bg-critical-bg px-2 py-1">
            {values.map((value, index) => (
              <div key={index} className="whitespace-nowrap font-mono text-xs text-critical">
                {value}
              </div>
            ))}
          </div>
        ) : (
          <code className="scroll-x min-w-0 flex-1 rounded border border-border bg-surface px-2 py-1 font-mono text-xs text-content-muted">
            {finding.value_masked}
          </code>
        )}
        {has && (
          <>
            <Button onClick={() => setRevealed((on) => !on)}>
              {revealed ? "Hide" : "Reveal"}
            </Button>
            {revealed && (
              <Button onClick={copy}>
                {copied ? "Copied" : values.length > 1 ? "Copy all" : "Copy"}
              </Button>
            )}
          </>
        )}
      </div>

      <p className="mt-1 text-xs text-content-subtle">
        {has
          ? "This run retained plaintext, so the real values are stored in the database and shown here on request."
          : "Only a masked value and a hash were stored. To see the real value, re-scan this artifact with “Retain full plaintext values” selected."}
      </p>
    </div>
  );
}

/**
 * The bytes around the hit. Masked by default; when the run retained
 * plaintext, click-to-reveal for the same reason as the value above.
 */
function ContextSnippet({ finding }: { finding: Finding }) {
  const [revealed, setRevealed] = useState(false);
  const plaintext = finding.context_plaintext;
  const showing = revealed && plaintext != null;

  return (
    <div>
      <div className="flex items-center gap-2">
        <Label>Context — {showing ? "plaintext" : "value masked"}</Label>
        {plaintext != null && (
          <Button
            onClick={(e) => {
              e.stopPropagation();
              setRevealed((on) => !on);
            }}
            className="!px-2 !py-0.5 !text-xs"
          >
            {revealed ? "Hide" : "Reveal"}
          </Button>
        )}
      </div>
      <pre
        className={`mt-1 scroll-x rounded border p-2 font-mono text-xs ${
          showing ? "border-critical/40 bg-critical-bg text-critical" : "border-border bg-surface"
        }`}
      >
        {showing ? plaintext : finding.context_snippet}
      </pre>
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[11px] font-medium uppercase tracking-wider text-content-subtle">
      {children}
    </span>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-content-subtle">{label}</dt>
      <dd className="mt-0.5 text-sm">{value}</dd>
    </div>
  );
}
