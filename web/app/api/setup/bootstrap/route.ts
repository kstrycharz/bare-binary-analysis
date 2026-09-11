/**
 * Completes first-time setup: mints the admin token and adopts it.
 *
 * A literal route, not the `[...path]` catch-all, for the same reason as
 * `setup/status` — plus this one has a side effect the catch-all cannot
 * perform: once the backend mints the token, this is where the dashboard
 * starts using it, via `setApiToken`. Every proxied request after this one
 * carries it, with no restart and no `.env` edit.
 */

import { NextResponse } from "next/server";
import { setApiToken } from "@/lib/runtime-token";

export const dynamic = "force-dynamic";

const API_URL = process.env.BARE_API_URL ?? "http://localhost:8000";

export async function POST() {
  let upstream: Response;
  try {
    upstream = await fetch(`${API_URL}/api/setup/bootstrap`, {
      method: "POST",
      cache: "no-store",
    });
  } catch (error) {
    return NextResponse.json(
      { detail: `could not reach the BARE API at ${API_URL}: ${String(error)}` },
      { status: 502 },
    );
  }

  const body = await upstream.json();
  if (upstream.ok && typeof body.token === "string") {
    setApiToken(body.token);
  }
  return NextResponse.json(body, { status: upstream.status });
}
