/**
 * Typed API client.
 *
 * **The `api` object is server-only.** It attaches the dashboard's credential,
 * which it reads from `./runtime-token` — a module that touches `node:fs`.
 * Importing `api` (or anything else non-type from this file) into a `"use
 * client"` component pulls `node:fs` into the browser bundle and fails the
 * webpack build outright. `tsc --noEmit` does not catch it; only a real
 * `next build` does.
 *
 * Client components talk to the backend with a bare
 * `fetch("/api/...")` against the proxy route, which attaches the same token
 * server-side. That is deliberate: a token in client JavaScript is a token any
 * page script can read, and the findings page is a list of exposed secrets.
 *
 * Types are safe to import anywhere — `import type` is erased at compile time.
 * Shared runtime values belong in a dependency-free module (see
 * `./severity.ts`), not here.
 */

import type { Severity } from "./severity";

export { SEVERITY_ORDER } from "./severity";
export type { Severity };

const SERVER_API = process.env.BARE_API_URL ?? "http://localhost:8000";

export function apiUrl(path: string): string {
  return typeof window === "undefined" ? `${SERVER_API}${path}` : path;
}

export interface RunSummary {
  id: string;
  status: string;
  profile: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  attested_by: string;
  attestation_reference: string;
  llm_enabled: boolean;
  retain_plaintext: boolean;
  /** When this run stops serving retained secret values; null if it kept none. */
  plaintext_expires_at: string | null;
  plaintext_purged_at: string | null;
  artifact_name: string | null;
  artifact_sha256: string | null;
  artifact_size_bytes: number | null;
  finding_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  /** Files analysed, including everything unpacked out of the artifact. */
  artifact_count: number;
  new_since_previous: number | null;
}

export interface Stage {
  analyzer: string;
  status: string;
  duration_s: number | null;
  exit_code: number | null;
  evidence_count: number;
  error: string | null;
  image_digest: string | null;
}

export interface Manifest {
  bare_version: string;
  artifact_sha256: string;
  rule_pack_version: string;
  rule_pack_hash: string;
  image_digests: Record<string, string>;
  tool_versions: Record<string, string>;
  fingerprint: string;
}

export interface ArtifactNode {
  id: string;
  name: string;
  path_in_tree: string;
  depth: number;
  sha256: string;
  size_bytes: number;
  kind: string;
  media_type: string | null;
  architecture: string | null;
  identified: Record<string, unknown>;
  finding_count: number;
  children: ArtifactNode[];
}

export interface RunDetail extends RunSummary {
  stages: Stage[];
  manifest: Manifest | null;
  artifact_tree: ArtifactNode | null;
  artifact_tree_truncated: boolean;
  previous_run_id: string | null;
  /** From the `summarize` role; null until someone asks for it. */
  llm_summary: string | null;
  llm_summary_model: string | null;
  llm_summary_at: string | null;
}

export interface FindingLocation {
  artifact_id: string;
  path_in_tree: string;
  offset: number | null;
  section: string | null;
  encoding: string | null;
  xref_function: string | null;
}

/** Every AI-derived field, in one object. The determinism toggle drops it whole. */
export interface LlmAssessment {
  verdict: string;
  reasoning: string | null;
  model: string | null;
  assessed_at: string | null;
}

export interface Finding {
  id: string;
  run_id: string;
  rule_id: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: number;
  value_masked: string;
  entropy: number | null;
  context_snippet: string | null;
  cwe: string | null;
  tags: string[];
  remediation_md: string | null;
  status: string;
  detected_by: string;
  is_new: boolean;
  locations: FindingLocation[];
  location_count: number;
  llm: LlmAssessment | null;
  /** Empty unless the run opted into plaintext retention. A clustered finding
   *  covers many distinct values, so this is a list rather than one string. */
  value_plaintexts: string[];
  /** From the `explain` role; null until someone asks for it. */
  llm_explanation: string | null;
  llm_explained_by: string | null;
  llm_explained_at: string | null;
  /** From the `investigate` role. The steps are the audit trail. */
  llm_investigation: string | null;
  llm_investigation_steps: InvestigationStep[];
  llm_investigation_confidence: string | null;
  llm_investigated_by: string | null;
  llm_investigated_at: string | null;
}

export interface InvestigationStep {
  tool: string;
  arguments: Record<string, unknown>;
  ok: boolean;
  output: string;
  detail: string;
}

export interface InvestigateResponse {
  run_id: string;
  finding_id: string;
  conclusion: string;
  confidence: string;
  steps: number;
  model: string;
  duration_s: number;
  redaction: string;
}

export interface ExplainResponse {
  run_id: string;
  finding_id: string;
  explanation: string;
  model: string;
  duration_s: number;
}

export interface SummaryResponse {
  run_id: string;
  summary: string;
  model: string;
  duration_s: number;
}

export interface ProviderHealth {
  name: string;
  healthy: boolean;
  model: string;
  detail: string;
  latency_s: number | null;
  is_local: boolean;
  available_models: string[];
}

export interface LlmSettings {
  enabled: boolean;
  egress: string;
  redaction: string;
  roles: Record<string, string>;
  providers: ProviderHealth[];
  config_path: string | null;
}

export interface RuleSummary {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  confidence: number;
  cwe: string | null;
  description: string;
  tags: string[];
}

export interface RulePackInfo {
  version: string;
  hash: string;
  rule_count: number;
  false_positive_corpus_size: number;
  rules: RuleSummary[];
}

export interface TriageResponse {
  run_id: string;
  triaged: number;
  confirmed: number;
  dismissed: number;
  needs_review: number;
  errors: number;
  duration_s: number;
  model: string;
}

/**
 * The dashboard's own credential, for server-side calls only.
 *
 * Server components talk to the API directly rather than through the proxy
 * route, so they have to present the token themselves — without this every
 * server-rendered page returns "a valid API token is required" the moment
 * authentication is switched on.
 *
 * `getApiToken` lives in `./runtime-token`, not here, because it touches
 * `node:fs` to read the token the setup wizard persisted — and this module is
 * imported by both server and client components. A dynamic `import()` behind
 * the `typeof window` guard keeps that file out of the browser bundle, where
 * bundling a `node:fs` import would fail the build outright rather than just
 * being dead code.
 */
async function serverAuthHeaders(): Promise<Record<string, string>> {
  if (typeof window !== "undefined") return {};
  const { getApiToken } = await import("./runtime-token");
  const token = getApiToken();
  return token ? { authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), {
    cache: "no-store",
    ...init,
    headers: { ...(await serverAuthHeaders()), ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* the body was not JSON; the status text will do */
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export const api = {
  listRuns: () => request<RunSummary[]>("/api/runs"),
  getRun: (id: string) => request<RunDetail>(`/api/runs/${id}`),
  listFindings: (runId: string, query = "") =>
    request<Finding[]>(`/api/runs/${runId}/findings${query}`),
  getFinding: (runId: string, id: string) =>
    request<Finding>(`/api/runs/${runId}/findings/${id}`),
  setFindingStatus: (runId: string, id: string, status: string, note?: string) =>
    request<Finding>(`/api/runs/${runId}/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note }),
    }),
  triage: (runId: string) =>
    request<TriageResponse>(`/api/runs/${runId}/triage`, { method: "POST" }),
  explain: (runId: string, findingId: string) =>
    request<ExplainResponse>(`/api/runs/${runId}/findings/${findingId}/explain`, {
      method: "POST",
    }),
  summarize: (runId: string) =>
    request<SummaryResponse>(`/api/runs/${runId}/summarize`, { method: "POST" }),
  llmSettings: () => request<LlmSettings>("/api/settings/llm"),
  rulePack: () => request<RulePackInfo>("/api/settings/rules"),
};

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function formatTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
