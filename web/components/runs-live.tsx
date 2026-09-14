"use client";

/**
 * Keeps the Runs list live without a manual reload.
 *
 * The list itself stays server-rendered (the §4 rule: the dashboard must
 * render usefully with JS disabled). This component adds only a wake-up
 * signal on top of that render, and fixes the two ways the page goes stale:
 *
 * 1. **Sitting on the page.** A run started from the CLI, from CI, or by a
 *    colleague never appeared, because nothing re-requested the server
 *    component. `/api/runs/events` emits whenever the ids-and-statuses
 *    fingerprint of the run list changes; each event triggers one
 *    `router.refresh()`, coalesced through a short quiet period so a burst of
 *    status changes is one refresh, not five.
 *
 * 2. **Navigating back to it.** Next's App Router caches RSC payloads
 *    client-side, so a `<Link>` back to `/` can serve what it rendered
 *    earlier even though the page is `force-dynamic` — the re-render happens
 *    per *request*, and nothing was making a request. The one refresh on mount
 *    pays for that: it is the same round-trip a hard reload already makes.
 *
 * The stream carries no run data — the refresh re-reads the real list from
 * the server, so there is no second source of truth to drift. When the tab is
 * hidden, the stream closes and reopens on return: background tabs should not
 * hold a poller, and "came back to find it had finished while I was away" is
 * what the on-return refresh is for.
 */

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

/** Statuses worth staying connected for. Past these the list is settled and
 *  only a *new* run can change it — which the stream still reports. */
const REFRESH_QUIET_MS = 400;

export function RunsLive({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [streaming, setStreaming] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let source: EventSource | null = null;

    const scheduleRefresh = () => {
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        timer.current = null;
        router.refresh();
      }, REFRESH_QUIET_MS);
    };

    const open = () => {
      if (source) return;
      source = new EventSource("/api/runs/events");
      source.onopen = () => setStreaming(true);
      source.onerror = () => setStreaming(false);
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as { changed?: boolean };
          // The first event after (re)connecting reports the baseline, not a
          // change; acting on it would refresh on every tab and mount.
          if (payload.changed) scheduleRefresh();
        } catch {
          /* a malformed frame is dropped, not trusted */
        }
      };
    };

    const close = () => {
      source?.close();
      source = null;
      setStreaming(false);
    };

    const onVisibility = () => {
      if (document.hidden) close();
      else {
        open();
        // Whatever finished while we were away should be visible on return,
        // without waiting for the next stream frame.
        scheduleRefresh();
      }
    };

    open();
    // One refresh on mount, deliberately: App Router keeps a client-side
    // cache of RSC payloads for back/forward navigation, so a `<Link>` home
    // can serve the list as of the last visit even through this page is
    // `force-dynamic` — re-rendering happens per *request*, and a client-side
    // navigation makes none. This is the most likely way a run started seconds
    // ago is missing from a page the operator just clicked to.
    scheduleRefresh();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      close();
      if (timer.current) clearTimeout(timer.current);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [router]);

  return (
    <div className="space-y-2">
      <p className="flex items-center gap-1.5 text-right text-[10.5px] uppercase tracking-[0.12em] text-content-subtle">
        <span
          aria-hidden
          className={`h-1.5 w-1.5 rounded-full ${streaming ? "bg-ok" : "bg-border"}`}
        />
        {streaming ? "live" : "reconnecting…"}
      </p>
      {children}
    </div>
  );
}
