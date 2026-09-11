/**
 * Runtime API proxy.
 *
 * Every browser-initiated call to the backend goes through here, on the
 * dashboard's own origin. That is why the backend ships no CORS configuration
 * at all: a findings page is a list of a company's exposed secrets and should
 * never be reachable cross-origin.
 *
 * Two deliberate choices, both learned the hard way:
 *
 * 1. **A Route Handler, not a `next.config` rewrite.** `rewrites()` is resolved
 *    at BUILD time and baked into the routes manifest, so an image built
 *    without BARE_API_URL set proxies to `localhost:8000` forever — which
 *    inside the web container is the web container. Server-rendered pages keep
 *    working because they read the env at runtime, so the symptom is baffling:
 *    every page loads and only uploads, triage, and status changes fail.
 *
 * 2. **`node:http`, not `fetch`.** Next patches global fetch, and the patched
 *    version does not carry `duplex: "half"` through, so a streamed request
 *    body fails with a bare "fetch failed". The same stream works fine through
 *    plain Node. Piping through `node:http` also means a 2 GB installer is
 *    never buffered in the dashboard's memory on its way past.
 */

import { IncomingMessage, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { NextRequest } from "next/server";
import { getApiToken } from "@/lib/runtime-token";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const API_URL = process.env.BARE_API_URL ?? "http://localhost:8000";

// Hop-by-hop headers, plus ones the upstream must compute for itself. `host`
// would break virtual-host routing; `content-length` would contradict a
// chunked streamed body.
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  // Whatever the browser sends is discarded and replaced below. The dashboard
  // authenticates as itself; letting a page script smuggle its own credential
  // through this proxy would make the server-side token pointless.
  "authorization",
  "x-bare-token",
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
]);

function proxy(request: NextRequest, path: string[]): Promise<Response> {
  const target = new URL(`${API_URL}/api/${path.join("/")}${request.nextUrl.search}`);
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;

  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    if (!STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) headers[key] = value;
  });

  // Set rather than defaulted: a browser must never be able to override the
  // dashboard's credential by sending its own Authorization header.
  const apiToken = getApiToken();
  if (apiToken) headers["authorization"] = `Bearer ${apiToken}`;

  return new Promise<Response>((resolve) => {
    const upstream = send(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method: request.method,
        headers,
      },
      (response: IncomingMessage) => {
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(response.headers)) {
          if (value === undefined || STRIPPED_RESPONSE_HEADERS.has(key.toLowerCase())) continue;
          responseHeaders.set(key, Array.isArray(value) ? value.join(", ") : value);
        }

        // Server-sent events must not be buffered anywhere along the path, or
        // live run progress arrives in one lump once the scan is already over.
        if (responseHeaders.get("content-type")?.includes("text/event-stream")) {
          responseHeaders.set("cache-control", "no-cache, no-transform");
          responseHeaders.set("x-accel-buffering", "no");
        }

        resolve(
          new Response(Readable.toWeb(response) as ReadableStream, {
            status: response.statusCode ?? 502,
            headers: responseHeaders,
          }),
        );
      },
    );

    upstream.on("error", (error: Error) => {
      resolve(
        Response.json(
          { detail: `Could not reach the BARE API at ${API_URL}: ${error.message}` },
          { status: 502 },
        ),
      );
    });

    if (request.method === "GET" || request.method === "HEAD" || request.body === null) {
      upstream.end();
      return;
    }

    // Streamed, not buffered: uploads are the whole point of this application
    // and they are large.
    const body = Readable.fromWeb(request.body as never);
    body.on("error", () => upstream.destroy());
    body.pipe(upstream);
  });
}

type Context = { params: Promise<{ path: string[] }> };

export async function GET(request: NextRequest, context: Context) {
  return proxy(request, (await context.params).path);
}

export async function POST(request: NextRequest, context: Context) {
  return proxy(request, (await context.params).path);
}

export async function PATCH(request: NextRequest, context: Context) {
  return proxy(request, (await context.params).path);
}

export async function PUT(request: NextRequest, context: Context) {
  return proxy(request, (await context.params).path);
}

export async function DELETE(request: NextRequest, context: Context) {
  return proxy(request, (await context.params).path);
}
