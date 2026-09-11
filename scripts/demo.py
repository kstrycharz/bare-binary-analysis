#!/usr/bin/env python3
"""End-to-end demonstration.

Uploads a planted artifact, waits for the scan, prints the findings, and — if a
model is configured — runs triage. Exists so that "does this actually work?"
has a one-command answer that exercises the real path: real HTTP, real queue,
real sandboxed container.

    make demo          (or)      ./make.ps1 demo
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT = REPO_ROOT / "tests" / "corpus" / "build" / "vulnerable-installer.exe"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
COLOURS = {
    "critical": "\033[31m",
    "high": "\033[33m",
    "medium": "\033[93m",
    "low": "\033[36m",
    "info": "\033[37m",
}


def request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 600,
) -> Any:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read()
    return json.loads(body) if body else None


def multipart(fields: dict[str, str], filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----bare-demo-boundary"
    parts: list[bytes] = []
    for name, value in fields.items():
        header = f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        parts.append(f"{header}{value}\r\n".encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
    )
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def wait_for_api(base: str, attempts: int = 60) -> None:
    for _ in range(attempts):
        try:
            request(f"{base}/healthz", timeout=5)
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(2)
    raise SystemExit(f"API at {base} never became reachable. Is the stack up? (make dev)")


def main() -> int:
    parser = argparse.ArgumentParser(description="BARE end-to-end demo")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--no-triage", action="store_true", help="skip the LLM triage pass")
    args = parser.parse_args()

    if not args.artifact.is_file():
        raise SystemExit(f"{args.artifact} not found. Run: make corpus")

    print(f"{BOLD}BARE demo{RESET}")
    print(f"{DIM}Waiting for the API…{RESET}")
    wait_for_api(args.api)

    content = args.artifact.read_bytes()
    body, content_type = multipart(
        {
            "attested_by": "demo@example.com",
            "attestation_reference": (
                "Synthetic corpus artifact built by tests/corpus/build_corpus.py; "
                "owned by this repository"
            ),
            "llm_enabled": "true",
        },
        args.artifact.name,
        content,
    )

    print(f"\n{BOLD}1. Upload{RESET}  {args.artifact.name} ({len(content):,} bytes)")
    created = request(
        f"{args.api}/api/runs",
        method="POST",
        data=body,
        headers={"Content-Type": content_type},
    )
    run_id = created["run_id"]
    print(f"   run {run_id}")
    print(f"   sha256 {created['artifact_sha256']}")

    print(f"\n{BOLD}2. Scan{RESET}  {DIM}(sandboxed container, no network){RESET}")
    run: dict[str, Any] = {}
    for _ in range(150):
        run = request(f"{args.api}/api/runs/{run_id}")
        if run["status"] in ("completed", "failed"):
            break
        time.sleep(2)
    else:
        raise SystemExit("scan did not finish within 5 minutes")

    if run["status"] == "failed":
        raise SystemExit(f"scan failed: {run.get('error')}")

    for stage in run["stages"]:
        print(
            f"   {stage['analyzer']:10} {stage['status']:10} "
            f"{stage['duration_s']:.2f}s  {stage['evidence_count']} evidence rows"
        )

    manifest = run.get("manifest") or {}
    if manifest:
        print(f"\n   {DIM}manifest fingerprint {manifest['fingerprint'][:16]}")
        print(f"   rule pack {manifest['rule_pack_version']} ({manifest['rule_pack_hash'][:12]})")
        digest = next(iter(manifest["image_digests"].values()))
        print(f"   image {digest[:40]}{RESET}")

    findings = request(f"{args.api}/api/runs/{run_id}/findings")
    print(f"\n{BOLD}3. Findings{RESET}  {len(findings)} deterministic")
    for finding in findings:
        colour = COLOURS.get(finding["severity"], "")
        location = finding["locations"][0] if finding["locations"] else {}
        offset = location.get("offset")
        where = f"0x{offset:x}" if offset is not None else "—"
        encoding = location.get("encoding") or "?"
        print(
            f"   {colour}{finding['severity']:8}{RESET} {finding['title'][:36]:36} "
            f"{finding['value_masked'][:24]:24} {DIM}{where:>8} {encoding}{RESET}"
        )

    wide = [f for f in findings if any(loc.get("encoding") == "utf-16le" for loc in f["locations"])]
    if wide:
        print(
            f"\n   {DIM}{len(wide)} of these are UTF-16LE only — a scanner that reads"
            f"\n   ASCII strings alone would have missed them entirely.{RESET}"
        )

    if args.no_triage:
        return 0

    print(f"\n{BOLD}4. AI triage{RESET}  {DIM}(advisory; findings above are unchanged){RESET}")
    try:
        result = request(f"{args.api}/api/runs/{run_id}/triage", method="POST", timeout=1800)
    except urllib.error.HTTPError as exc:
        detail = json.loads(exc.read() or b"{}").get("detail", str(exc))
        print(f"   {DIM}skipped: {detail}{RESET}")
        print(
            f"   {DIM}The deterministic report above stands unchanged — that is the point.{RESET}"
        )
        return 0

    print(
        f"   {result['model']}: {result['triaged']} triaged in {result['duration_s']:.1f}s "
        f"— {result['confirmed']} confirmed, {result['dismissed']} dismissed, "
        f"{result['needs_review']} need review"
    )

    triaged = request(f"{args.api}/api/runs/{run_id}/findings")
    for finding in triaged:
        if finding.get("llm"):
            print(f"\n   {BOLD}{finding['title']}{RESET} → {finding['llm']['verdict']}")
            print(f"   {DIM}{finding['llm']['reasoning']}{RESET}")

    print(f"\n{BOLD}Open the dashboard:{RESET} http://localhost:3000/runs/{run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
