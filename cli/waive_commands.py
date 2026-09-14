"""``bare waive``: turn a finding id from a red build into a well-formed waiver.

Offline on purpose. It needs the policy and the waiver file, both of which live
in the release repository, and nothing from the server — so it works on the
laptop of whoever is looking at the failed build, with no token that can read
findings (ADR-0019).
"""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Annotated

import typer

from cli.scan_commands import _fail
from core.policy import (
    POLICY_DIR,
    WAIVERS_FILE,
    PolicyLoadError,
    discover_policy,
    load_policy,
    parse_policy,
)
from core.policy.waive import WaiveError, append_waiver, build_waiver, parse_expiry


def waive(
    finding_id: Annotated[str, typer.Argument(help="The full finding id, as printed by the gate.")],
    reason: Annotated[
        str, typer.Option(help="Why this is safe to ship for now. Reviewers read this.")
    ] = "",
    expires: Annotated[
        str, typer.Option(help="YYYY-MM-DD, or a number of days such as 30d. Required.")
    ] = "",
    owner: Annotated[
        str,
        typer.Option(envvar="BARE_WAIVER_OWNER", help="Who answers for this waiver."),
    ] = "",
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Policy file. Defaults to the nearest .bare/policy.yaml."),
    ] = None,
    waivers: Annotated[
        Path | None,
        typer.Option("--waivers", help="Waiver file. Defaults to waivers.yaml beside the policy."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the entry and write nothing.")
    ] = False,
) -> None:
    """Add a time-boxed waiver for one finding to .bare/waivers.yaml.

    Checked against the same policy the gate uses, so a waiver this writes is
    one the gate will honour:

        bare waive 3f2a91c4e8b7d05a9c1e44b2d7f08a61 \\
            --reason "Vendor SDK sample key, confirmed inert (SEC-4471)" \\
            --owner kyle@example.com --expires 30d
    """
    if not expires.strip():
        # No default, deliberately. A waiver with no end date outlives the
        # reason it was granted and the person who granted it.
        _fail("--expires is required: a date (YYYY-MM-DD) or a number of days such as 30d")

    policy_path = policy
    if policy_path is not None and not policy_path.is_file():
        _fail(f"policy file {policy_path} does not exist")
    if policy_path is None:
        policy_path = discover_policy(Path.cwd())

    try:
        loaded = load_policy(policy_path) if policy_path is not None else parse_policy({})
    except PolicyLoadError as exc:
        _fail(str(exc))

    if waivers is not None:
        target = waivers
    elif policy_path is not None:
        target = policy_path.parent / WAIVERS_FILE
    else:
        target = Path.cwd() / POLICY_DIR / WAIVERS_FILE

    today = date.today()
    try:
        waiver = build_waiver(
            finding_id=finding_id,
            reason=reason,
            owner=owner,
            expires=parse_expiry(expires, today),
            policy=loaded,
            today=today,
        )
        raw = target.read_bytes() if target.is_file() else b""
        existing = raw.decode("utf-8").replace("\r\n", "\n")
        updated = append_waiver(existing, waiver, loaded, source=str(target))
    except WaiveError as exc:
        _fail(str(exc))
    except UnicodeDecodeError:
        _fail(f"{target} is not UTF-8 text")

    days = (waiver.expires - today).days
    if dry_run:
        # Only the addition, unless the append had to rewrite a line above it
        # (`waivers: []`), in which case the slice would be misaligned.
        addition = updated[len(existing) :] if updated.startswith(existing) else updated
        typer.echo(addition, nl=False)
        typer.echo(f"dry run: nothing written to {target}", err=True)
        return

    # Keep the file's line endings. A Windows checkout rewritten from CRLF to
    # LF turns a one-entry change into a whole-file diff, which is exactly the
    # review this file is supposed to get.
    newline = "\r\n" if b"\r\n" in raw else "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline=newline) as handle:
        handle.write(updated)
    os.replace(temporary, target)

    typer.secho(f"waived {waiver.finding_id} in {target}", fg=typer.colors.GREEN)
    typer.echo(
        f"  expires {waiver.expires.isoformat()} ({days} day(s); "
        f"policy {loaded.name!r} allows {loaded.max_waiver_days})"
    )
    typer.echo("Commit it: waivers are reviewed like code.")
