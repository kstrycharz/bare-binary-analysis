/**
 * Whether the dashboard needs to run first-time setup.
 *
 * A literal route, not the `[...path]` catch-all: the catch-all attaches the
 * dashboard's own credential to every request, and before setup completes
 * there is no credential to attach. This one is deliberately unauthenticated,
 * forwarding straight to the backend's equally unauthenticated
 * `GET /api/setup/status` (guarded there by "no token exists yet", not by
 * anything this route needs to enforce itself).
 */

import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const API_URL = process.env.BARE_API_URL ?? "http://localhost:8000";

export async function GET() {
  try {
    const upstream = await fetch(`${API_URL}/api/setup/status`, { cache: "no-store" });
    const body = await upstream.json();
    return NextResponse.json(body, { status: upstream.status });
  } catch (error) {
    // Fail closed on "needs setup", not open: if the API cannot be reached at
    // all, redirecting to a wizard that would fail the same way is worse than
    // letting the page render its own "could not reach the API" error.
    return NextResponse.json(
      { needs_setup: false, error: `could not reach the BARE API: ${String(error)}` },
      { status: 502 },
    );
  }
}
