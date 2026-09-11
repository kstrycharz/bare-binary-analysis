/**
 * Gates every page behind first-time setup.
 *
 * A fresh deployment has no API token, and every page but `/setup` would just
 * render a wall of 401s from the proxy. Checking here, once, before any page
 * renders, means the dashboard's very first screen is useful instead of
 * broken.
 *
 * Calls the backend directly rather than through the `/api/setup/status`
 * route: that route exists for the *browser* to call, and going through it
 * here would just add a hop to the same request.
 */

import { NextResponse, type NextRequest } from "next/server";

const API_URL = process.env.BARE_API_URL ?? "http://localhost:8000";

export const config = {
  // Everything except Next's own internals and the proxy — the proxy must
  // stay reachable unconditionally, including by this very check.
  matcher: ["/((?!_next|api/|favicon.ico).*)"],
};

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname === "/setup") {
    return NextResponse.next();
  }

  let needsSetup = false;
  try {
    const response = await fetch(`${API_URL}/api/setup/status`, { cache: "no-store" });
    if (response.ok) {
      needsSetup = (await response.json()).needs_setup === true;
    }
  } catch {
    // Fail open: an unreachable API is a different problem than an
    // unconfigured one, and the page's own error state explains it better
    // than a redirect to a wizard that would fail identically.
  }

  if (needsSetup) {
    return NextResponse.redirect(new URL("/setup", request.url));
  }
  return NextResponse.next();
}
