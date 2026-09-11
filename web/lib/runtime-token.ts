/**
 * The dashboard's own API credential, resolved once and kept mutable.
 *
 * `BARE_TOKEN` (env) is still honoured for anyone who sets it, but
 * requiring it is exactly the manual `.env` step the setup wizard exists to
 * remove. When it is absent, the token instead comes from whatever the wizard
 * most recently minted through `POST /api/setup/bootstrap` — kept in memory
 * for this process, and written to disk so a container *restart* (not a
 * volume wipe) does not ask again.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const TOKEN_FILE = process.env.BARE_TOKEN_FILE ?? "/app/data/api-token";

let cached: string | null = null;

function readPersisted(): string {
  try {
    return readFileSync(TOKEN_FILE, "utf-8").trim();
  } catch {
    return "";
  }
}

export function getApiToken(): string {
  if (cached !== null) return cached;
  cached = process.env.BARE_TOKEN?.trim() || readPersisted();
  return cached;
}

export function setApiToken(token: string): void {
  cached = token;
  try {
    mkdirSync(dirname(TOKEN_FILE), { recursive: true });
    writeFileSync(TOKEN_FILE, token, { mode: 0o600 });
  } catch (error) {
    // Persistence failing must not fail the request that just minted this
    // token — the wizard still shows it, and the dashboard keeps working
    // in-process until the next restart loses the in-memory copy too.
    console.error("bare: could not persist the API token to disk", error);
  }
}
