"use client";

/**
 * Live scan progress over Server-Sent Events.
 *
 * SSE rather than WebSocket (§4): it survives corporate proxies that mangle
 * upgrade handshakes, and the browser reconnects on its own. When the run
 * reaches a terminal state the page refreshes once so the server-rendered
 * report appears — no client-side duplication of the report view.
 *
 * The bar advances on *phase*, never on a clock. A scan of a 213 MB installer
 * spends five minutes inside one analyzer, and a bar that crept forward on a
 * timer would be inventing the one thing the operator came here to learn. Each
 * phase is a state the pipeline is observably in; the fill is discrete and the
 * current phase is named. Where a real estimate exists — this same artifact has
 * been scanned before — it is shown and labelled as coming from that run.
 *
 * "Show logs" opens each stage's analyzer output as it is printed (ADR-0033),
 * for the scan that looks stuck or is about to degrade. Off by default, and
 * remembered per browser: it is a debugging view, not the progress panel.
 */

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Button, Panel, StatusDot, duration } from "@/components/ui";
import { LiveStageLog } from "@/components/live-stage-log";

interface StageEvent {
  /** Absent from an API older than live logs; such a stage simply has none. */
  id?: string;
  analyzer: string;
  status: string;
  duration_s: number | null;
}

interface ProgressEvent {
  status: string;
  phase: string;
  stages: StageEvent[];
  finding_count: number;
  artifact_count: number;
  started_at: string | null;
  expected_s: number | null;
  error?: string;
}

/** Must match SCAN_PHASES in api/routers/runs.py. */
const PHASES: { key: string; label: string; detail: string }[] = [
  { key: "queued", label: "Queued", detail: "Waiting for a worker to pick up the run" },
  { key: "unpack", label: "Unpack", detail: "Recursively extracting nested containers" },
  { key: "index", label: "Index", detail: "Recording the artifact tree" },
  { key: "static", label: "Scan", detail: "Extracting strings and matching rules" },
  { key: "report", label: "Report", detail: "Correlating evidence into findings" },
];

const TERMINAL = new Set(["completed", "degraded", "failed", "cancelled"]);

const SHOW_LOGS_KEY = "bare.run-progress.show-logs";

function useElapsed(startedAt: string | null): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  if (!startedAt) return null;
  return Math.max(0, (now - new Date(startedAt).getTime()) / 1000);
}

/** A per-browser preference. Storage can be absent or throw (private windows,
 *  blocked site data); the panel then just starts with logs hidden. */
function useShowLogs(): [boolean, () => void] {
  const [show, setShow] = useState(false);
  useEffect(() => {
    try {
      setShow(window.localStorage.getItem(SHOW_LOGS_KEY) === "1");
    } catch {
      /* default stands */
    }
  }, []);
  function toggle() {
    setShow((previous) => {
      const next = !previous;
      try {
        window.localStorage.setItem(SHOW_LOGS_KEY, next ? "1" : "0");
      } catch {
        /* the toggle still works for this page view */
      }
      return next;
    });
  }
  return [show, toggle];
}

export function RunProgress({
  runId,
  initialStatus,
}: {
  runId: string;
  initialStatus: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<ProgressEvent>({
    status: initialStatus,
    phase: initialStatus === "queued" ? "queued" : "unpack",
    stages: [],
    finding_count: 0,
    artifact_count: 0,
    started_at: null,
    expected_s: null,
  });
  const [connected, setConnected] = useState(false);
  const [showLogs, toggleLogs] = useShowLogs();
  const refreshed = useRef(false);

  useEffect(() => {
    const source = new EventSource(`/api/runs/${runId}/events`);

    source.onopen = () => setConnected(true);
    source.onmessage = (event) => {
      const payload = JSON.parse(event.data) as ProgressEvent;
      setState(payload);
      // `degraded` is terminal too — a scan whose analyzer did not finish is
      // over, and leaving the stream open would hang this panel on a run that
      // already has a report waiting for it.
      if (TERMINAL.has(payload.status) && !refreshed.current) {
        refreshed.current = true;
        source.close();
        router.refresh();
      }
    };
    source.onerror = () => setConnected(false);

    return () => source.close();
  }, [runId, router]);

  const elapsed = useElapsed(state.started_at);
  const index = Math.max(
    0,
    PHASES.findIndex((phase) => phase.key === state.phase),
  );
  const done = state.phase === "done";
  // A phase name the client does not know about must not blank the panel; fall
  // back to the first phase rather than rendering nothing.
  const current = PHASES[index] ?? PHASES[0]!;

  // Discrete: the fraction of phases finished. Never interpolated within a
  // phase, because nothing is known about progress inside one.
  const percent = done ? 100 : Math.round((index / PHASES.length) * 100);

  const logStages = state.stages.filter(
    (stage): stage is StageEvent & { id: string } => typeof stage.id === "string",
  );

  return (
    <Panel
      title="Scanning"
      actions={
        <>
          <span className="text-xs text-content-subtle">
            {connected ? "live" : "reconnecting…"}
          </span>
          <Button
            type="button"
            variant="ghost"
            onClick={toggleLogs}
            aria-pressed={showLogs}
            aria-controls="scan-logs"
          >
            {showLogs ? "Hide logs" : "Show logs"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 px-4 py-4">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span className="text-sm font-medium">{done ? "Finishing up" : current.label}</span>
          <span className="text-xs text-content-subtle">{current.detail}</span>
          <span className="ml-auto font-mono text-xs tnum text-content-muted">
            {elapsed !== null ? duration(elapsed) : "—"}
            {state.expected_s !== null && !done && (
              <span className="text-content-subtle">
                {" / ~"}
                {duration(state.expected_s)}
              </span>
            )}
          </span>
        </div>

        <div
          className="h-1.5 w-full overflow-hidden rounded-full bg-surface-sunken"
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Scan progress: ${current.label}`}
        >
          <div
            className="h-full rounded-full bg-accent transition-[width] duration-500 ease-out"
            style={{ width: `${percent}%` }}
          />
        </div>

        <ol className="flex flex-wrap gap-x-4 gap-y-1">
          {PHASES.map((phase, position) => {
            const reached = done || position < index;
            const active = !done && position === index;
            return (
              <li
                key={phase.key}
                className={
                  "flex items-center gap-1.5 text-xs " +
                  (active
                    ? "text-content"
                    : reached
                      ? "text-content-muted"
                      : "text-content-subtle")
                }
              >
                <span
                  aria-hidden
                  className={
                    "size-1.5 rounded-full " +
                    (reached
                      ? "bg-ok"
                      : active
                        ? "bg-accent animate-pulse"
                        : "bg-border")
                  }
                />
                {phase.label}
              </li>
            );
          })}
        </ol>

        {state.expected_s !== null && !done && (
          <p className="text-xs text-content-subtle">
            Estimate from the previous scan of this same artifact, not a prediction — a scan
            is as long as the file count it unpacks to.
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t border-border px-4 py-2.5 text-xs">
        <StatusDot status={state.status} />
        {state.artifact_count > 1 && (
          <span className="tnum text-content-muted">
            {state.artifact_count.toLocaleString()} artifacts found
          </span>
        )}
        <span className="tnum text-content-muted">
          {state.finding_count} finding{state.finding_count === 1 ? "" : "s"} so far
        </span>
      </div>

      {showLogs ? (
        <div id="scan-logs" className="border-t border-border">
          {logStages.length === 0 ? (
            <p className="px-4 py-3 text-xs text-content-subtle">
              No analyzer has started yet. Its output appears here once the first container
              does.
            </p>
          ) : (
            logStages.map((stage) => (
              <LiveStageLog
                key={stage.id}
                runId={runId}
                stageId={stage.id}
                analyzer={stage.analyzer}
                status={stage.status}
              />
            ))
          )}
        </div>
      ) : (
        state.stages.length > 0 && (
          <ul className="border-t border-border">
            {state.stages.map((stage) => (
              <li
                key={stage.analyzer}
                className="flex flex-wrap items-center gap-3 border-b border-border/60 px-4 py-2 last:border-0"
              >
                <span className="w-16 shrink-0 font-mono text-xs">{stage.analyzer}</span>
                <StatusDot status={stage.status} />
                {stage.duration_s !== null && (
                  <span className="ml-auto text-xs tnum text-content-subtle">
                    {duration(stage.duration_s)}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )
      )}
    </Panel>
  );
}
