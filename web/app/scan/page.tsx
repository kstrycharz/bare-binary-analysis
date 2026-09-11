"use client";

/**
 * Upload.
 *
 * The attestation gate is configurable and currently off for prototyping, so
 * this is deliberately frictionless: pick a file, scan it. The optional
 * reference field still writes to the audit log when filled in, so turning the
 * gate back on later does not leave a hole where these runs were.
 */

import { useRouter } from "next/navigation";
import { useCallback, useRef, useState } from "react";
import { Button, ErrorNotice, Panel, bytes } from "@/components/ui";

const SUPPORTED = [
  "Installers — MSI, NSIS, InnoSetup, self-extracting EXE",
  "Archives — zip, 7z, tar.gz, CAB, ISO, RAR, JAR, APK",
  "Executables — PE, ELF, Mach-O, .NET",
  "Firmware — squashfs, cpio, and images 7z can open",
  "App bundles — Electron ASAR, PyInstaller",
];

export default function ScanPage() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [reference, setReference] = useState("");
  const [llmEnabled, setLlmEnabled] = useState(true);
  const [retainPlaintext, setRetainPlaintext] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) setFile(dropped);
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;

    setSubmitting(true);
    setError(null);

    const body = new FormData();
    body.append("file", file);
    body.append("llm_enabled", String(llmEnabled));
    body.append("retain_plaintext", String(retainPlaintext));
    if (reference.trim()) body.append("attestation_reference", reference.trim());

    try {
      const response = await fetch("/api/runs", { method: "POST", body });
      if (!response.ok) {
        const detail = (await response.json().catch(() => ({}))) as { detail?: string };
        throw new Error(detail.detail ?? response.statusText);
      }
      const created = (await response.json()) as { run_id: string };
      router.push(`/runs/${created.run_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-3xl space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">New scan</h1>
        <p className="mt-1 text-sm text-content-muted">
          Upload what you are about to ship. Nested containers are unpacked
          recursively and everything inside is scanned.
        </p>
      </header>

      <Panel>
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          className={`m-4 cursor-pointer rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors ${
            dragging
              ? "border-accent bg-accent-muted"
              : "border-border-strong hover:border-accent hover:bg-surface-sunken"
          }`}
        >
          <input
            ref={inputRef}
            id="file"
            type="file"
            required
            className="sr-only"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
          {file ? (
            <>
              <p className="font-medium">{file.name}</p>
              <p className="mt-1 text-sm text-content-muted">{bytes(file.size)}</p>
              <p className="mt-2 text-xs text-content-subtle">
                Click or drop another file to replace
              </p>
            </>
          ) : (
            <>
              <p className="text-sm font-medium">Drop an artifact here</p>
              <p className="mt-1 text-sm text-content-muted">or click to browse</p>
            </>
          )}
        </div>

        <div className="border-t border-border px-4 py-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-content-subtle">
            Unpacked recursively
          </p>
          <ul className="mt-1.5 grid gap-x-6 gap-y-0.5 text-xs text-content-muted sm:grid-cols-2">
            {SUPPORTED.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </Panel>

      <Panel title="Options">
        <div className="space-y-4 px-4 py-4">
          <label className="flex items-start gap-2.5 text-sm">
            <input
              type="checkbox"
              checked={llmEnabled}
              onChange={(e) => setLlmEnabled(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              Enable AI triage
              <span className="mt-0.5 block text-xs text-content-muted">
                Optional. The scan finds the same things either way — triage
                only classifies and explains them. Masked values and context go
                to your configured model; secret plaintext never does.
              </span>
            </span>
          </label>

          <fieldset>
            <legend className="text-sm font-medium">Secret value retention</legend>
            <div className="mt-1.5 space-y-2">
              <label className="flex items-start gap-2.5 text-sm">
                <input
                  type="radio"
                  name="retain_plaintext"
                  checked={!retainPlaintext}
                  onChange={() => setRetainPlaintext(false)}
                  className="mt-0.5"
                />
                <span>
                  Masked and hashed only
                  <span className="mt-0.5 block text-xs text-content-muted">
                    Default. What the report and dashboard show — nothing else
                    is stored for a finding's value.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2.5 text-sm">
                <input
                  type="radio"
                  name="retain_plaintext"
                  checked={retainPlaintext}
                  onChange={() => setRetainPlaintext(true)}
                  className="mt-0.5"
                />
                <span>
                  Retain full plaintext values for this run
                  <span className="mt-0.5 block text-xs text-content-muted">
                    Writes the actual secret value into the database,
                    unencrypted, with no expiry and no page in this dashboard
                    that reads it back — retrieving it means a direct SQL
                    query against the evidence table. Turn this on only if you
                    already have a process for that.
                  </span>
                </span>
              </label>
            </div>
          </fieldset>

          <div>
            <label
              htmlFor="reference"
              className="block text-sm font-medium"
            >
              Authorization reference{" "}
              <span className="font-normal text-content-subtle">(optional)</span>
            </label>
            <input
              id="reference"
              type="text"
              value={reference}
              onChange={(e) => setReference(e.target.value)}
              placeholder="RELEASE-4821 — internal release gate"
              className="mt-1.5 w-full rounded-md border border-border bg-surface px-3 py-1.5 text-sm placeholder:text-content-subtle"
            />
            <p className="mt-1 text-xs text-content-muted">
              Recorded in the audit log and stamped into reports. The
              attestation gate is disabled for prototyping — set{" "}
              <code className="font-mono">BARE_REQUIRE_ATTESTATION=true</code>{" "}
              to make this mandatory before analysing artifacts you did not
              build.
            </p>
          </div>
        </div>
      </Panel>

      {error && <ErrorNotice title="Upload failed" detail={error} />}

      <div className="flex items-center gap-3">
        <Button type="submit" variant="primary" disabled={!file || submitting}>
          {submitting ? "Uploading…" : "Start scan"}
        </Button>
        {file && !submitting && (
          <span className="text-xs text-content-subtle">
            {bytes(file.size)} — analysis begins immediately
          </span>
        )}
      </div>
    </form>
  );
}
