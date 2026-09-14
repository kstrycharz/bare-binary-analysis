#!/usr/bin/env python3
"""Regenerate the README screenshots from a running stack.

Screenshots rot the moment the UI changes, so they are produced by this script
rather than captured by hand. It drives the real product the way a first-time
user does — the setup wizard, an upload, the run page — against a stack seeded
only with the synthetic corpus.

    docker compose up --build -d          # a FRESH stack: no tokens, no runs
    uv run playwright install chromium    # once
    uv run python scripts/screenshots.py  # or: make screenshots

§9 applies to pictures. Everything on screen comes from
``tests/corpus/build_corpus.py``, whose planted values are provably invalid;
plaintext retention is left off, and no screen that shows a token is captured.
Run it against a throwaway stack, never one holding real scans.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from playwright.sync_api import Locator, Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS = REPO_ROOT / "tests" / "corpus" / "build"
ATTESTATION = "README screenshots, synthetic corpus only"


def _request(url: str, *, token: str = "", method: str = "GET", **kwargs: Any) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers.update(kwargs.pop("headers", {}))
    req = urllib.request.Request(url, method=method, headers=headers, **kwargs)
    with urllib.request.urlopen(req, timeout=120) as response:
        body = response.read()
    return json.loads(body) if body else None


def _wait_for(url: str, what: str, attempts: int = 90) -> None:
    for _ in range(attempts):
        try:
            urllib.request.urlopen(url, timeout=5).close()
            return
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(2)
    raise SystemExit(f"{what} at {url} never became reachable — is the stack up?")


def _upload(api: str, token: str, artifact: Path) -> str:
    boundary = "----bare-screenshots"
    fields = {
        "attested_by": "screenshots@example.com",
        "attestation_reference": ATTESTATION,
        "profile": "standard",
        "llm_enabled": "false",
        "retain_plaintext": "false",
    }
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        for k, v in fields.items()
    ]
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{artifact.name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
    )
    parts += [artifact.read_bytes(), f"\r\n--{boundary}--\r\n".encode()]
    created = _request(
        f"{api}/api/runs",
        token=token,
        method="POST",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    return str(created["run_id"])


def _wait_for_run(api: str, token: str, run_id: str, timeout_s: int = 600) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        run = _request(f"{api}/api/runs/{run_id}", token=token)
        if run["status"] in {"completed", "degraded", "failed", "cancelled"}:
            return dict(run)
        time.sleep(3)
    raise SystemExit(f"run {run_id} did not finish within {timeout_s}s")


def _settle(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)  # charts animate in


def _shot(page: Page, out: Path, name: str, **kwargs: Any) -> None:
    path = out / f"{name}.png"
    page.screenshot(path=str(path), **kwargs)
    print(f"  wrote {path.relative_to(REPO_ROOT)} ({path.stat().st_size // 1024} KB)")


def _shot_element(locator: Locator, out: Path, name: str) -> None:
    """Capture one element. Playwright scrolls it into view and sizes the image
    to it — computing a clip by hand mixes viewport and page coordinates, which
    is how an earlier version captured the wrong half of the run page."""
    path = out / f"{name}.png"
    locator.screenshot(path=str(path))
    print(f"  wrote {path.relative_to(REPO_ROOT)} ({path.stat().st_size // 1024} KB)")


def _setup_wizard(page: Page, web: str, out: Path) -> str:
    """Walk the first-run wizard, capturing it before any token is on screen."""
    page.goto(f"{web}/setup")
    _settle(page)
    _shot(page, out, "setup-wizard")

    page.get_by_role("button", name="Generate admin token").click()
    token = page.locator("code").filter(has_text="bare_").first.inner_text(timeout=30_000)
    page.get_by_role("button", name="Next: connect a model").click()
    page.get_by_text("Connect a model").first.wait_for()
    _settle(page)
    _shot(page, out, "setup-model")
    page.get_by_role("button", name="Skip for now").click()
    page.wait_for_url(f"{web}/", timeout=30_000)
    return token.strip()


def _gate_terminal(page: Page, api: str, token: str, run_id: str, out: Path) -> None:
    """Render `bare gate` output as a terminal, since that is where CI users meet it."""
    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "gate", run_id, "--api", api, "--token", token],
        capture_output=True,
        # The CLI forces UTF-8 on its own streams; decoding with the Windows
        # code page instead renders every em dash as mojibake.
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    transcript = f"$ bare gate {run_id[:8]}…\n{result.stdout}\n$ echo $?\n{result.returncode}"
    page.set_content(
        "<body style='margin:0;background:#0d1117'>"
        "<pre style='display:inline-block;margin:0;padding:20px 24px;color:#e6edf3;"
        "background:#0d1117;font:13px/1.45 ui-monospace,Consolas,monospace;white-space:pre'>"
        f"{html.escape(transcript)}</pre></body>"
    )
    page.locator("pre").screenshot(path=str(out / "gate-blocked.png"))
    print(f"  wrote docs/images/gate-blocked.png (exit {result.returncode})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--web", default="http://localhost:3000")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "images")
    parser.add_argument("--token", default="", help="Admin token, if the stack is already set up.")
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    installer = CORPUS / "vulnerable-installer.exe"
    nested = CORPUS / "nested-release.zip"
    if not installer.is_file() or not nested.is_file():
        subprocess.run([sys.executable, "tests/corpus/build_corpus.py"], cwd=REPO_ROOT, check=True)

    _wait_for(f"{args.api}/healthz", "the API")
    _wait_for(args.web, "the dashboard")
    needs_setup = bool(_request(f"{args.api}/api/setup/status")["needs_setup"])

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})

        token = args.token
        if needs_setup:
            print("walking the setup wizard")
            token = _setup_wizard(page, args.web, out)
        elif not token:
            raise SystemExit("the stack is already set up; pass --token, or use a fresh stack")

        print("seeding runs from the synthetic corpus")
        nested_run = _upload(args.api, token, nested)
        installer_run = _upload(args.api, token, installer)
        for run_id in (nested_run, installer_run):
            run = _wait_for_run(args.api, token, run_id)
            print(f"  {run_id[:8]} {run['status']}: {run['finding_count']} finding(s)")

        print("capturing the dashboard")
        page.goto(f"{args.web}/")
        _settle(page)
        _shot(page, out, "runs")

        page.goto(f"{args.web}/scan")
        _settle(page)
        _shot(page, out, "new-scan")

        page.goto(f"{args.web}/runs/{installer_run}")
        _settle(page)
        _shot(page, out, "run-overview")

        findings = page.locator("table").filter(has=page.get_by_text("Location")).first
        findings.scroll_into_view_if_needed()
        findings.locator("tbody tr").first.click()
        _settle(page)
        _shot_element(findings, out, "findings")

        page.goto(f"{args.web}/runs/{nested_run}")
        _settle(page)
        # Panels are <section>s titled by an <h2>; the tree is the one titled so.
        tree = page.locator("section").filter(
            has=page.get_by_role("heading", name="Artifact tree", exact=True)
        )
        for _ in range(6):  # expand nested containers level by level
            closed = tree.locator("button[aria-expanded='false']")
            if closed.count() == 0:
                break
            for _ in range(closed.count()):
                closed.nth(0).click()
        _settle(page)
        _shot_element(tree, out, "artifact-tree")

        page.goto(f"{args.web}/rules")
        _settle(page)
        _shot(page, out, "rules")

        _gate_terminal(page, args.api, token, installer_run, out)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
