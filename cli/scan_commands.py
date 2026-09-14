"""The CI-facing commands: ``scan``, ``gate``, and ``policy``.

``bare scan`` is the whole product from a pipeline's point of view. It
uploads the artifact the build just produced, waits for the scan, evaluates the
release policy, writes the machine-readable artefacts a pipeline wants, and
exits with a code that means something:

    0  pass          — release may proceed
    1  blocked       — policy violation
    2  error         — could not scan (unreachable API, bad policy, timeout)
    3  inconclusive  — the scan did not complete; the artifact was not fully seen

Exit code 2 is kept strictly separate from 1 throughout. "The scanner was down"
and "your installer ships an AWS key" demand different responses from a release
engineer, and a tool that returns the same code for both trains people to
re-run until it goes green.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from cli.client import ApiError, BareClient
from cli.gate_output import render_json, render_markdown, render_text
from core.policy import (
    POLICY_DIR,
    POLICY_FILE,
    WAIVERS_FILE,
    GateDecision,
    GateVerdict,
    PolicyLoadError,
    discover_policy,
    load_policy,
    parse_policy,
    verdict_from_dict,
)

# Shared with the API and the `scan --sbom` path so all three emit the same
# bytes for one run; a hand-rolled json.dumps here would be a third spelling
# of a document whose whole value is being byte-stable.
from reporting.cyclonedx import dump_sbom
from reporting.sbom_diff import SbomDiffError, diff_sboms
from reporting.sbom_diff import render_json as render_sbom_diff_json
from reporting.sbom_diff import render_text as render_sbom_diff_text

EXIT_ERROR = 2

policy_app = typer.Typer(help="Release-policy operations.", no_args_is_help=True)


# NoReturn, not None: every caller relies on this raising, and several read
# a value assigned in the `try` block immediately afterwards. Typed as None,
# that looks like a possibly-unbound bug to anyone auditing the file.
def _fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(EXIT_ERROR)


def _read_optional(path: Path | None) -> str:
    if path is None:
        return ""
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _resolve_policy_path(explicit: Path | None, artifact: Path) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            _fail(f"policy file {explicit} does not exist")
        return explicit
    return discover_policy(artifact.parent if artifact.is_file() else Path.cwd())


def _default_attestation() -> tuple[str, str]:
    """Derive the attestation from the CI environment.

    The gate is only as good as its audit trail, and "who authorised this
    scan" answered by hand on a build agent is answered wrong. These are the
    variables the major platforms already set; anything unrecognised falls back
    to explicit flags, which stay required.
    """
    actor = (
        os.environ.get("GITHUB_ACTOR")
        or os.environ.get("GITLAB_USER_LOGIN")
        or os.environ.get("BUILD_REQUESTEDFOR")
        or os.environ.get("CHANGE_AUTHOR")
        or ""
    )
    reference = (
        _github_run_url()
        or os.environ.get("CI_PIPELINE_URL")
        or os.environ.get("BUILD_BUILDURI")
        or os.environ.get("BUILD_URL")
        or ""
    )
    return actor, reference


def _github_run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return ""


def _write_job_summary(markdown: str) -> None:
    """Append to the GitHub Actions job summary when running there.

    Best-effort by design: a summary that cannot be written must never turn a
    passing gate into a failed step.
    """
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    try:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    except OSError as exc:  # pragma: no cover - environment-specific
        typer.secho(
            f"warning: could not write job summary: {exc}",
            fg=typer.colors.YELLOW,
            err=True,
        )


def scan(
    artifact: Annotated[Path, typer.Argument(help="The built artifact to scan.")],
    api: Annotated[
        str, typer.Option(envvar="BARE_API_URL", help="BARE API base URL.")
    ] = "http://localhost:8000",
    token: Annotated[
        str,
        typer.Option(envvar="BARE_TOKEN", help="Bearer token, if the deployment needs one."),
    ] = "",
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Policy file. Defaults to .bare/policy.yaml."),
    ] = None,
    waivers: Annotated[
        Path | None,
        typer.Option("--waivers", help="Waiver file. Defaults to .bare/waivers.yaml."),
    ] = None,
    baseline_run: Annotated[
        str, typer.Option(help="Compare against this run id instead of the last same-named run.")
    ] = "",
    attested_by: Annotated[
        str, typer.Option(envvar="BARE_ATTESTED_BY", help="Who authorises this scan.")
    ] = "",
    attestation_ref: Annotated[
        str,
        typer.Option(envvar="BARE_ATTESTATION_REF", help="Ticket, contract, or pipeline URL."),
    ] = "",
    profile: Annotated[str, typer.Option(help="quick | standard | deep.")] = "standard",
    llm: Annotated[bool, typer.Option("--llm/--no-llm", help="Enable AI triage.")] = False,
    timeout: Annotated[int, typer.Option(help="Seconds to wait for the scan.")] = 1800,
    poll_interval: Annotated[float, typer.Option(help="Seconds between status polls.")] = 5.0,
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF here for code scanning.")] = None,
    pdf: Annotated[Path | None, typer.Option(help="Write the PDF release record here.")] = None,
    sbom: Annotated[Path | None, typer.Option(help="Write a CycloneDX SBOM here.")] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the verdict as JSON.")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Write a Markdown summary here.")
    ] = None,
    warn_only: Annotated[
        bool, typer.Option(help="Report the verdict but always exit 0. For onboarding.")
    ] = False,
) -> None:
    """Upload an artifact, wait for the scan, and enforce the release policy."""
    if not artifact.is_file():
        _fail(f"{artifact} is not a file")

    # --- resolve the policy before uploading -----------------------------
    # A malformed policy should fail the build in two seconds, not after a
    # twenty-minute scan of a 2 GB installer.
    policy_path = _resolve_policy_path(policy, artifact)
    policy_yaml = ""
    if policy_path is not None:
        policy_yaml = policy_path.read_text(encoding="utf-8")
        try:
            loaded = load_policy(policy_path)
        except PolicyLoadError as exc:
            _fail(str(exc))
        typer.echo(f"policy: {loaded.name} ({policy_path})")
    else:
        typer.echo(
            f"policy: built-in defaults (no {POLICY_DIR}/{POLICY_FILE} found — "
            "blocking at high and above, new findings only)"
        )

    waiver_path = waivers
    if waiver_path is None and policy_path is not None:
        candidate = policy_path.parent / WAIVERS_FILE
        waiver_path = candidate if candidate.is_file() else None
    waivers_yaml = _read_optional(waiver_path)
    if waiver_path is not None and waivers_yaml:
        typer.echo(f"waivers: {waiver_path}")

    env_actor, env_ref = _default_attestation()
    attested_by = attested_by or env_actor
    attestation_ref = attestation_ref or env_ref
    if not attested_by or not attestation_ref:
        # Deliberately not defaulted to something like "ci". The attestation is
        # a real gate, and an unattributable one is worse than an absent one.
        _fail(
            "an attestation is required: pass --attested-by and --attestation-ref, "
            "or run in a CI environment that sets them"
        )

    client = BareClient(api, token=token)

    # --- upload ----------------------------------------------------------
    typer.echo(f"uploading {artifact.name} ({artifact.stat().st_size:,} bytes) to {api}")
    try:
        handle = client.upload(
            artifact,
            attested_by=attested_by,
            attestation_reference=attestation_ref,
            profile=profile,
            llm_enabled=llm,
        )
    except ApiError as exc:
        _fail(f"{exc}{chr(10) + exc.body if exc.body else ''}")

    typer.echo(f"run {handle.run_id} queued (sha256 {handle.artifact_sha256[:16]}…)")

    # --- wait ------------------------------------------------------------
    seen: set[str] = set()

    def _progress(run: dict[str, object]) -> None:
        status = str(run.get("status", ""))
        if status not in seen:
            seen.add(status)
            typer.echo(f"  status: {status}")

    try:
        client.wait_for_run(
            handle.run_id, timeout_s=timeout, poll_interval_s=poll_interval, on_poll=_progress
        )
    except ApiError as exc:
        _fail(str(exc))

    # --- gate ------------------------------------------------------------
    try:
        payload = client.get_gate(
            handle.run_id,
            policy_yaml=policy_yaml,
            waivers_yaml=waivers_yaml,
            baseline_run_id=baseline_run,
        )
    except ApiError as exc:
        _fail(f"{exc}{chr(10) + exc.body if exc.body else ''}")

    try:
        verdict = verdict_from_dict(payload)
    except (KeyError, ValueError) as exc:
        _fail(f"could not read the gate response: {exc}")

    _emit_verdict(
        verdict,
        client=client,
        api=api,
        run_id=handle.run_id,
        artifact_name=artifact.name,
        baseline=str(payload.get("baseline", "")),
        json_out=json_out,
        markdown_out=markdown_out,
        sarif=sarif,
        pdf=pdf,
        sbom=sbom,
        warn_only=warn_only,
    )


def _emit_verdict(
    verdict: GateVerdict,
    *,
    client: BareClient,
    api: str,
    run_id: str,
    artifact_name: str,
    baseline: str,
    json_out: Path | None,
    markdown_out: Path | None,
    sarif: Path | None,
    pdf: Path | None,
    sbom: Path | None,
    warn_only: bool,
) -> NoReturn:
    """Render a verdict, write the requested artefacts, and exit.

    Shared by `scan` and `gate` so the two can never disagree about what a
    verdict looks like or which exit code it carries — the whole point of the
    gate is that its answer is the same however you asked for it.
    """
    run_url = f"{api.rstrip('/')}/runs/{run_id}"
    typer.echo("")
    typer.echo(render_text(verdict, artifact=artifact_name, run_url=run_url))

    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            render_json(verdict, run_id=run_id, artifact=artifact_name, baseline=baseline),
            encoding="utf-8",
        )
        typer.echo(f"wrote {json_out}")

    markdown = render_markdown(verdict, artifact=artifact_name, run_url=run_url)
    if markdown_out is not None:
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.write_text(markdown, encoding="utf-8")
        typer.echo(f"wrote {markdown_out}")
    _write_job_summary(markdown)

    if sarif is not None:
        try:
            document = client.get_sarif(run_id)
        except ApiError as exc:
            _fail(f"could not fetch SARIF: {exc}")
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        typer.echo(f"wrote {sarif}")

    if sbom is not None:
        try:
            document = client.get_sbom(run_id)
        except ApiError as exc:
            _fail(f"could not fetch the SBOM: {exc}")
        sbom.parent.mkdir(parents=True, exist_ok=True)
        # Not a local json.dumps: this one omitted ensure_ascii=False, so a
        # component with a non-ASCII name serialised differently here than
        # through the API — two spellings of a document whose entire value is
        # being byte-identical across exports.
        sbom.write_text(dump_sbom(document), encoding="utf-8")
        count = len(document.get("components", []))
        typer.echo(f"wrote {sbom} ({count} component(s))")

    if pdf is not None:
        try:
            document = client.get_pdf(run_id)
        except ApiError as exc:
            _fail(f"could not fetch the PDF report: {exc}")
        pdf.parent.mkdir(parents=True, exist_ok=True)
        pdf.write_bytes(document)
        typer.echo(f"wrote {pdf}")

    if warn_only and verdict.decision is not GateDecision.PASS:
        typer.secho(
            "warn-only: the gate would have failed this build", fg=typer.colors.YELLOW, err=True
        )
        raise typer.Exit(0)

    raise typer.Exit(verdict.exit_code)


def gate(
    run_id: Annotated[str, typer.Argument(help="An existing run id to re-evaluate.")],
    api: Annotated[
        str, typer.Option(envvar="BARE_API_URL", help="BARE API base URL.")
    ] = "http://localhost:8000",
    token: Annotated[
        str,
        typer.Option(envvar="BARE_TOKEN", help="Bearer token, if the deployment needs one."),
    ] = "",
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Policy file. Defaults to .bare/policy.yaml."),
    ] = None,
    waivers: Annotated[
        Path | None,
        typer.Option("--waivers", help="Waiver file. Defaults to .bare/waivers.yaml."),
    ] = None,
    baseline_run: Annotated[
        str, typer.Option(help="Compare against this run id instead of the linked predecessor.")
    ] = "",
    sarif: Annotated[Path | None, typer.Option(help="Write SARIF here for code scanning.")] = None,
    pdf: Annotated[Path | None, typer.Option(help="Write the PDF release record here.")] = None,
    sbom: Annotated[Path | None, typer.Option(help="Write a CycloneDX SBOM here.")] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the verdict as JSON.")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Write a Markdown summary here.")
    ] = None,
    warn_only: Annotated[bool, typer.Option(help="Report the verdict but always exit 0.")] = False,
) -> None:
    """Re-evaluate an existing run against a policy, without re-uploading.

    The verdict is a separate call from the scan precisely so this is possible
    (ADR-0015): re-gating a 2 GB installer under a corrected policy, or under a
    stricter one on a release branch, should not mean scanning it again.

    Also the honest way to answer "would this policy change have blocked last
    week's release?" — point it at the run and find out.
    """
    policy_path = _resolve_policy_path(policy, Path.cwd())
    policy_yaml = ""
    if policy_path is not None:
        policy_yaml = policy_path.read_text(encoding="utf-8")
        try:
            loaded = load_policy(policy_path)
        except PolicyLoadError as exc:
            _fail(str(exc))
        typer.echo(f"policy: {loaded.name} ({policy_path})")
    else:
        typer.echo(f"policy: built-in defaults (no {POLICY_DIR}/{POLICY_FILE} found)")

    waiver_path = waivers
    if waiver_path is None and policy_path is not None:
        candidate = policy_path.parent / WAIVERS_FILE
        waiver_path = candidate if candidate.is_file() else None
    waivers_yaml = _read_optional(waiver_path)

    client = BareClient(api, token=token)
    try:
        payload = client.get_gate(
            run_id,
            policy_yaml=policy_yaml,
            waivers_yaml=waivers_yaml,
            baseline_run_id=baseline_run,
        )
    except ApiError as exc:
        _fail(f"{exc}{chr(10) + exc.body if exc.body else ''}")

    try:
        verdict = verdict_from_dict(payload)
    except (KeyError, ValueError) as exc:
        _fail(f"could not read the gate response: {exc}")

    _emit_verdict(
        verdict,
        client=client,
        api=api,
        run_id=run_id,
        artifact_name=str(payload.get("artifact", "")) or run_id,
        baseline=str(payload.get("baseline", "")),
        json_out=json_out,
        markdown_out=markdown_out,
        sarif=sarif,
        pdf=pdf,
        sbom=sbom,
        warn_only=warn_only,
    )


@policy_app.command("validate")
def policy_validate(
    path: Annotated[Path | None, typer.Argument(help="Policy file to check.")] = None,
) -> None:
    """Check a policy file and print what it would enforce.

    Worth its own command: this is the check that belongs on a pull request
    touching the policy, where the alternative is finding out at release time.
    """
    target = path or (Path.cwd() / POLICY_DIR / POLICY_FILE)
    if not target.is_file():
        _fail(f"{target} does not exist")

    try:
        loaded = load_policy(target)
    except PolicyLoadError as exc:
        _fail(str(exc))

    typer.secho(f"{target} is valid", fg=typer.colors.GREEN)
    typer.echo(f"  name              : {loaded.name}")
    floor = loaded.block_at_or_above.value if loaded.block_at_or_above else "disabled"
    typer.echo(f"  blocks at/above   : {floor}")
    if loaded.block_rules:
        typer.echo(f"  blocked rules     : {', '.join(sorted(loaded.block_rules))}")
    if loaded.block_categories:
        typer.echo(f"  blocked categories: {', '.join(sorted(loaded.block_categories))}")
    typer.echo(f"  baseline mode     : {loaded.baseline_mode.value}")
    typer.echo(f"  on degraded scan  : {loaded.on_degraded.value}")
    typer.echo(f"  trusts AI verdicts: {loaded.trust_llm_dismissals}")
    typer.echo(f"  max waiver days   : {loaded.max_waiver_days}")


@policy_app.command("init")
def policy_init(
    directory: Annotated[Path, typer.Argument(help="Repository root.")] = Path(),
    force: Annotated[bool, typer.Option(help="Overwrite an existing policy.")] = False,
) -> None:
    """Write a starter policy into ``.bare/``."""
    target_dir = directory / POLICY_DIR
    target = target_dir / POLICY_FILE
    if target.exists() and not force:
        _fail(f"{target} already exists; pass --force to overwrite")

    template = Path(__file__).resolve().parents[1] / "config" / "policy.example.yaml"
    if not template.is_file():
        _fail(f"the packaged policy template is missing at {template}")

    target_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    typer.secho(f"wrote {target}", fg=typer.colors.GREEN)
    typer.echo("Review it, commit it, and wire `bare scan` into your release pipeline.")


@policy_app.command("explain")
def policy_explain() -> None:
    """Print the built-in defaults, which apply when no policy file is found."""
    defaults = parse_policy({})
    typer.echo("Built-in defaults (used when no .bare/policy.yaml is present):")
    typer.echo(f"  block at or above : {defaults.block_at_or_above}")
    typer.echo(f"  baseline mode     : {defaults.baseline_mode.value}")
    typer.echo(f"  on degraded scan  : {defaults.on_degraded.value}")
    typer.echo(f"  trust AI verdicts : {defaults.trust_llm_dismissals}")
    typer.echo("")
    typer.echo("Exit codes: 0 pass, 1 blocked, 2 error, 3 inconclusive.")
    sys.stdout.flush()


def sbom(
    run_id: Annotated[str, typer.Argument(help="The run to export.")],
    api: Annotated[
        str, typer.Option(envvar="BARE_API_URL", help="BARE API base URL.")
    ] = "http://localhost:8000",
    token: Annotated[
        str,
        typer.Option(envvar="BARE_TOKEN", help="Bearer token, if the deployment needs one."),
    ] = "",
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Write here instead of stdout."),
    ] = None,
) -> None:
    """Export a CycloneDX SBOM for a run that has already been scanned.

    `scan --sbom` writes one as a side effect of scanning. This exists for
    everything after that: attaching a bill of materials to a release that was
    built last week, re-exporting after a component detector improves, or
    diffing two runs. The document is rebuilt from the stored inventory rather
    than re-scanning, so it is byte-identical to the one the original scan
    produced and can be hashed.

    Writes to stdout by default so it pipes:

        bare sbom RUN_ID | jq '.components | length'
    """
    client = BareClient(api, token=token)
    try:
        document = client.get_sbom(run_id)
    except ApiError as exc:
        _fail(f"could not fetch the SBOM: {exc}")

    rendered = dump_sbom(document)
    if out is None:
        # `typer.echo` rather than print: the document is already newline
        # terminated, and Windows consoles need the encoding shim above.
        typer.echo(rendered, nl=False)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8")
    count = len(document.get("components", []))
    typer.echo(f"wrote {out} ({count} component(s))")


def sbom_diff(
    before: Annotated[str, typer.Argument(help="Earlier build: a run id or an SBOM file.")],
    after: Annotated[str, typer.Argument(help="Later build: a run id or an SBOM file.")],
    api: Annotated[
        str, typer.Option(envvar="BARE_API_URL", help="BARE API base URL.")
    ] = "http://localhost:8000",
    token: Annotated[
        str,
        typer.Option(envvar="BARE_TOKEN", help="Bearer token, if the deployment needs one."),
    ] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print the diff as JSON.")] = False,
    exit_code: Annotated[
        bool,
        typer.Option("--exit-code", help="Exit 1 when the components differ, like `git diff`."),
    ] = False,
) -> None:
    """Report components added, removed, and changed between two builds.

    Each side is a run id, fetched from the API, or a path to an SBOM file —
    so two SBOMs attached to releases months apart can be compared without the
    runs that produced them. An existing file wins over a run id of the same
    spelling.

        bare sbom-diff RUN_LAST_RELEASE RUN_THIS_BUILD
        bare sbom-diff v2.4-sbom.json v2.5-sbom.json --json
    """
    client: BareClient | None = None

    def load(reference: str) -> tuple[dict[str, Any], str]:
        nonlocal client
        path = Path(reference)
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8")), path.name
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                _fail(f"could not read {path} as JSON: {exc}")
        if client is None:
            client = BareClient(api, token=token)
        try:
            return client.get_sbom(reference), ""
        except ApiError as exc:
            _fail(f"could not fetch the SBOM for {reference!r}: {exc}")

    old, old_label = load(before)
    new, new_label = load(after)
    try:
        diff = diff_sboms(old, new, before_label=old_label, after_label=new_label)
    except SbomDiffError as exc:
        _fail(str(exc))

    typer.echo(render_sbom_diff_json(diff) if as_json else render_sbom_diff_text(diff), nl=False)
    if exit_code and diff.has_changes:
        raise typer.Exit(1)
