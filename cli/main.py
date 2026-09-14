"""The ``bare`` command-line interface.

M0 exposes the sandbox operations only. ``bare scan`` lands in M1 once
there is an ingest pipeline for it to drive.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from core.config import BARE_VERSION, get_settings
from core.logging import configure_logging


def _use_utf8_console() -> None:
    """Token prefixes, unpack-tree separators and severity glyphs are all
    non-ASCII, and a Windows console defaults to cp1252 — which renders them as
    mojibake, or kills the command outright with a UnicodeEncodeError partway
    through output it has already computed. Windows is a first-class
    environment here (ADR-0006), and this is what makes it behave like one."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_use_utf8_console()

app = typer.Typer(
    name="bare",
    help="Scan the artifacts you are about to ship for exposed secrets and IP.",
    no_args_is_help=True,
    add_completion=False,
)
sandbox_app = typer.Typer(help="Sandbox runtime operations.", no_args_is_help=True)
app.add_typer(sandbox_app, name="sandbox")

# The CI-facing surface. Imported eagerly because `bare scan --help` on a
# build agent must not depend on a database or a Docker socket being reachable.
from cli.scan_commands import gate, policy_app, sbom, sbom_diff, scan  # noqa: E402
from cli.token_commands import token_app  # noqa: E402

app.command("scan")(scan)
app.command("gate")(gate)
app.command("sbom")(sbom)
app.command("sbom-diff")(sbom_diff)
app.add_typer(policy_app, name="policy")
app.add_typer(token_app, name="token")


@app.command()
def version() -> None:
    """Print the BARE version."""
    typer.echo(BARE_VERSION)


@sandbox_app.command("health")
def sandbox_health() -> None:
    """Check that the configured sandbox runtime is usable."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_output=False)

    from core.sandbox import driver_from_settings

    driver = driver_from_settings()
    try:
        health = driver.health()
    finally:
        driver.close()

    typer.echo(f"driver:   {health.driver}")
    typer.echo(f"healthy:  {health.healthy}")
    if health.version:
        typer.echo(f"version:  {health.version}")
    if health.detail:
        typer.echo(f"detail:   {health.detail}")
    for warning in health.warnings:
        typer.secho(f"warning:  {warning}", fg=typer.colors.YELLOW)
    raise typer.Exit(0 if health.healthy else 1)


@sandbox_app.command("hello")
def sandbox_hello(
    image: Annotated[
        str | None,
        typer.Option(help="Analyzer image to run. Defaults to the configured tag."),
    ] = None,
    keep: Annotated[bool, typer.Option(help="Keep the temporary run directory.")] = False,
) -> None:
    """Run the reference analyzer end-to-end through the real driver.

    This is the M0 acceptance check: it proves an analyzer container runs
    inside the locked-down sandbox and returns output. The probe results it
    prints are observed *from inside* the container, so a boundary that is not
    actually there shows up here.
    """
    settings = get_settings()
    configure_logging(level=settings.log_level, json_output=False)

    from core.sandbox import BindMount, MountMode, SandboxSpec, driver_from_settings
    from core.sandbox.images import analyzer_image
    from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR

    settings.run_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="hello-", dir=settings.run_root))
    staging = run_dir / "staging"
    results = run_dir / "results"
    staging.mkdir()
    results.mkdir()
    # Analyzers run as uid 10001 and must be able to write results.
    _make_writable(results)
    (staging / "sample.txt").write_text(
        "BARE reference input. Contains no secrets.\n", encoding="utf-8"
    )

    driver = driver_from_settings()
    try:
        spec = SandboxSpec(
            image=image or analyzer_image("hello"),
            run_id=run_dir.name,
            analyzer="hello",
            command=("--probe",),
            timeout_s=60,
            mounts=(
                BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
            ),
        )
        result = driver.run(spec)
    finally:
        driver.close()

    typer.echo(f"status:    {result.status}")
    typer.echo(f"exit code: {result.exit_code}")
    typer.echo(f"duration:  {result.duration_s:.2f}s")
    typer.echo(f"image:     {result.image_digest or 'unknown digest'}")
    if result.error:
        typer.secho(f"error:     {result.error}", fg=typer.colors.RED)
    if result.stdout:
        typer.echo(f"stdout:    {result.stdout.decode('utf-8', 'replace').strip()}")
    if result.stderr:
        typer.secho(
            f"stderr:    {result.stderr.decode('utf-8', 'replace').strip()}",
            fg=typer.colors.YELLOW,
        )

    result_file = results / "result.json"
    exit_code = 0
    if result_file.is_file():
        payload = json.loads(result_file.read_text(encoding="utf-8"))
        typer.echo("\nisolation probe (observed from inside the container):")
        probe = payload.get("probe", {})
        typer.echo(f"  uid/gid: {probe.get('uid')}:{probe.get('gid')}")
        exit_code = _report_probe(probe)
    else:
        typer.secho("no result.json was produced", fg=typer.colors.RED)
        exit_code = 1

    if keep:
        typer.echo(f"\nrun directory kept at {run_dir}")
    else:
        shutil.rmtree(run_dir, ignore_errors=True)
    raise typer.Exit(exit_code)


# Operations the sandbox must forbid; anything succeeding here is a broken boundary.
_MUST_FAIL = {
    "write_rootfs",
    "write_input",
    "tcp_connect",
    "dns_resolve",
    "unshare_userns",
    "ptrace_self",
}
_MUST_SUCCEED = {"write_work_tmpfs", "write_output"}


def _report_probe(probe: dict[str, object]) -> int:
    attempts = probe.get("attempts")
    if not isinstance(attempts, list):
        typer.secho("  probe produced no attempts", fg=typer.colors.RED)
        return 1

    failed = False
    if probe.get("is_root"):
        typer.secho("  FAIL container is running as root", fg=typer.colors.RED)
        failed = True

    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        action = str(attempt.get("action"))
        succeeded = bool(attempt.get("succeeded"))
        if action in _MUST_FAIL:
            ok = not succeeded
            expectation = "blocked"
        elif action in _MUST_SUCCEED:
            ok = succeeded
            expectation = "allowed"
        else:
            continue
        mark = "ok  " if ok else "FAIL"
        colour = typer.colors.GREEN if ok else typer.colors.RED
        detail = attempt.get("error") or ("succeeded" if succeeded else "failed")
        typer.secho(f"  {mark} {action}: expected {expectation}, got {detail}", fg=colour)
        failed = failed or not ok

    return 1 if failed else 0


def _make_writable(path: Path) -> None:
    """Grant the analyzer uid write access to the results directory.

    No-op on Windows, where Docker Desktop's bind mounts do not carry POSIX
    ownership and the container sees a permissive mount already.
    """
    import os

    if os.name == "nt":
        return
    from core.sandbox.spec import ANALYZER_GID, ANALYZER_UID

    try:
        os.chown(path, ANALYZER_UID, ANALYZER_GID)
    except PermissionError:
        # Non-root dev environments: fall back to world-writable. Acceptable
        # for a per-run temp directory; the production worker runs as root
        # inside its own container and takes the chown path.
        path.chmod(0o777)


if __name__ == "__main__":
    app()
