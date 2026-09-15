"use client";

/**
 * One stage's analyzer output while the scan is still running (ADR-0033).
 *
 * Polls the endpoint `StageLogDisclosure` reads. While the stage runs, that
 * serves a snapshot the worker republishes every few seconds — redacted with
 * the run's own rule pack, each stream's unfinished last line held back. When
 * the stage ends the snapshot is replaced by the retained log, and the effect
 * below runs once more on that transition so the panel settles on it.
 *
 * Same trust story as `StageLogDisclosure`, for the same reason: this is
 * untrusted output derived from a customer's binary. It becomes a text node
 * inside a `<pre>` and nothing else — no markup, no ANSI colouring, no
 * linkifying. Each of those would be a parser pointed at the artifact.
 */

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { StatusDot } from "@/components/ui";

const POLL_MS = 3000;
const UNFINISHED = new Set(["pending", "running"]);

/** `X-Bare-Log-State` when there is text, plus the states without any. */
type LogState = "waiting" | "live" | "partial" | "final" | "none" | "denied";

const STATE_LABEL: Record<LogState, string> = {
  waiting: "waiting for output",
  live: "live · redacted",
  partial: "last snapshot · stage did not finish",
  final: "retained log",
  none: "no log retained",
  denied: "needs an admin token",
};

export function LiveStageLog({
  runId,
  stageId,
  analyzer,
  status,
}: {
  runId: string;
  stageId: string;
  analyzer: string;
  status: string;
}) {
  const running = UNFINISHED.has(status);
  const [text, setText] = useState<string | null>(null);
  const [state, setState] = useState<LogState>("waiting");
  const [error, setError] = useState<string | null>(null);
  const hasText = useRef(false);
  const denied = useRef(false);
  const pre = useRef<HTMLPreElement>(null);
  // Follow the tail, unless the reader has scrolled up to look at something.
  const following = useRef(true);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function load() {
      if (denied.current) return;
      try {
        const response = await fetch(`/api/runs/${runId}/stages/${stageId}/logs`, {
          cache: "no-store",
        });
        if (cancelled) return;
        if (response.status === 401 || response.status === 403) {
          denied.current = true;
          setState("denied");
          return;
        }
        if (response.status === 404) {
          // While the stage runs this is "nothing printed yet". After it ends
          // it is "nothing was retained" — and if a snapshot is already on
          // screen, that snapshot is all there will ever be.
          setState(running ? "waiting" : hasText.current ? "partial" : "none");
          setError(null);
        } else if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          if (!cancelled) setError(body.detail ?? `HTTP ${response.status}`);
        } else {
          const body = await response.text();
          if (cancelled) return;
          const header = response.headers.get("x-bare-log-state");
          hasText.current = true;
          setText(body);
          setState(header === "live" || header === "partial" ? header : "final");
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      }
      if (!cancelled && running) timer = setTimeout(load, POLL_MS);
    }

    void load();
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [runId, stageId, running]);

  useLayoutEffect(() => {
    const element = pre.current;
    if (element && following.current) element.scrollTop = element.scrollHeight;
  }, [text]);

  return (
    <section
      aria-label={`${analyzer} output`}
      className="border-b border-border/60 last:border-0"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-xs">
        <span className="font-mono">{analyzer}</span>
        <StatusDot status={status} />
        <span
          className={`ml-auto ${state === "denied" ? "text-high" : "text-content-subtle"}`}
        >
          {STATE_LABEL[state]}
        </span>
      </div>
      {error && <p className="px-4 pb-2 text-xs text-critical">{error}</p>}
      {text !== null ? (
        <pre
          ref={pre}
          role="log"
          aria-live="off"
          tabIndex={0}
          onScroll={(event) => {
            const element = event.currentTarget;
            following.current =
              element.scrollHeight - element.scrollTop - element.clientHeight < 24;
          }}
          className="mx-4 mb-3 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-surface-sunken px-3 py-2 font-mono text-[11px] leading-relaxed"
        >
          {text}
        </pre>
      ) : state === "waiting" ? (
        <p className="px-4 pb-3 text-xs text-content-subtle">
          Nothing printed yet. Output shows up a few seconds after the analyzer writes it.
        </p>
      ) : state === "denied" ? (
        <p className="px-4 pb-3 text-xs text-content-subtle">
          Analyzer logs are admin-scoped, and the dashboard&apos;s API token is not an admin
          token.
        </p>
      ) : null}
    </section>
  );
}
