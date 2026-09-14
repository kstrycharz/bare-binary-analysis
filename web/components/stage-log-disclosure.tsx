"use client";

/**
 * The retained analyzer output for one stage (bounty: `analyzer-logs`).
 *
 * A row expander in the stages table. Fetched on click, never on render: the
 * log lives in object storage behind the ADMIN-scoped endpoint, and a panel
 * that pulled every stage's output for every page view would be a bulk read
 * of masked-secret-adjacent text nobody asked for.
 *
 * **The log is untrusted output derived from a customer's binary.** It is
 * rendered as text inside a `<pre>` — React escapes it, the endpoint serves
 * `text/plain` with `default-src 'none'; sandbox`, and nothing here parses it
 * as markup or feeds it to `dangerouslySetInnerHTML`. That chain is the
 * entire defence and each link is load-bearing; do not "improve" any of it
 * into a markdown renderer.
 */

import { useState } from "react";
import { bytes } from "@/components/ui";

export function StageLogDisclosure({
  runId,
  stageId,
  logBytes,
  logTruncated,
  degraded,
}: {
  runId: string;
  stageId: string;
  logBytes: number | null;
  logTruncated: boolean;
  degraded: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (!next || text !== null || loading) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/runs/${runId}/stages/${stageId}/logs`);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail ?? `HTTP ${response.status}`);
      }
      setText(await response.text());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  // No bytes on the row at all: a stage from before retention, or a bucket
  // write that failed. Nothing to expand.
  if (logBytes === null) {
    return <span className="text-content-subtle">—</span>;
  }

  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className={`text-left text-xs underline-offset-2 hover:underline ${
          degraded ? "text-high" : "text-content-muted"
        }`}
      >
        {bytes(logBytes)}
        {logTruncated ? " (truncated)" : ""}
        {open ? " ▴" : " ▾"}
      </button>
      {open && (
        <div className="mt-2 rounded border border-border bg-surface-sunken">
          {loading && <p className="px-3 py-2 text-xs text-content-subtle">loading…</p>}
          {error && <p className="px-3 py-2 text-xs text-critical">{error}</p>}
          {text !== null && (
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words px-3 py-2 font-mono text-[11px] leading-relaxed">
              {text}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
