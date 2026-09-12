"""`bare token` — mint, list, and revoke API credentials.

These talk to the **database directly**, not to the API, and so must be run
where the database is reachable — on the server, or in the API container. That
is deliberate: a credential-minting endpoint reachable over the network is a
privilege-escalation target, and the one operation that must never depend on
already having a token is creating the first one.

    docker compose exec api bare token create ci-pipeline --scope ci
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, NoReturn

import typer

from core.auth import Scope

token_app = typer.Typer(help="Manage API tokens (run on the server).", no_args_is_help=True)

EXIT_ERROR = 2


def _fail(message: str) -> NoReturn:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(EXIT_ERROR)


@token_app.command("create")
def token_create(
    name: Annotated[str, typer.Argument(help="Label, e.g. 'github-actions release'.")],
    scope: Annotated[
        str, typer.Option(help="ci = submit and gate. admin = everything, incl. findings.")
    ] = "ci",
    expires_in_days: Annotated[int, typer.Option(help="Days until expiry. 0 means no expiry.")] = 0,
    created_by: Annotated[str, typer.Option(help="Who is minting this.")] = "cli",
) -> None:
    """Mint a token. The plaintext is printed once and never stored."""
    try:
        chosen = Scope(scope.strip().lower())
    except ValueError:
        _fail(f"unknown scope {scope!r}; expected one of {[s.value for s in Scope]}")

    from core.db import session_scope
    from core.pipeline.tokens import TokenError, create_token

    try:
        with session_scope() as session:
            minted = create_token(
                session,
                name=name,
                scope=chosen,
                created_by=created_by,
                expires_in_days=expires_in_days or None,
            )
            # Read what we need before the session closes; the ORM object is
            # not usable afterwards and the plaintext exists only here.
            payload = (minted.token, minted.name, minted.scope.value, minted.expires_at)
    except TokenError as exc:
        _fail(str(exc))
    except Exception as exc:  # database unreachable, schema missing, …
        _fail(f"could not create the token: {exc}")

    plaintext, label, scope_value, expires = payload
    typer.secho(f"created token {label!r} (scope: {scope_value})", fg=typer.colors.GREEN)
    typer.echo("")
    typer.secho(f"  {plaintext}", fg=typer.colors.CYAN, bold=True)
    typer.echo("")
    typer.echo("This is shown once and cannot be recovered. Store it now.")
    if expires is not None:
        typer.echo(f"Expires: {expires.isoformat()}")
    else:
        typer.secho(
            "No expiry set. Prefer --expires-in-days for CI credentials.",
            fg=typer.colors.YELLOW,
        )


@token_app.command("list")
def token_list(
    include_revoked: Annotated[bool, typer.Option(help="Show revoked tokens too.")] = False,
) -> None:
    """List tokens. Never prints a secret — only the redacted prefix."""
    from core.db import session_scope
    from core.pipeline.tokens import list_tokens

    try:
        with session_scope() as session:
            rows = [
                (
                    t.name,
                    t.token_prefix,
                    t.scope,
                    t.created_at,
                    t.expires_at,
                    t.revoked_at,
                    t.last_used_at,
                    t.use_count or 0,
                )
                for t in list_tokens(session, include_revoked=include_revoked)
            ]
    except Exception as exc:
        _fail(f"could not read tokens: {exc}")

    if not rows:
        typer.echo("no tokens")
        return

    now = datetime.now(UTC)
    header = f"{'NAME':<26} {'PREFIX':<16} {'SCOPE':<6} {'STATUS':<10} {'USED':>6}  LAST USED"
    typer.echo(header)
    typer.echo("-" * len(header))
    for name, prefix, scope, _created, expires, revoked, last_used, uses in rows:
        if revoked is not None:
            state, colour = "revoked", typer.colors.RED
        elif expires is not None and _naive(expires) <= _naive(now):
            state, colour = "expired", typer.colors.RED
        else:
            state, colour = "active", typer.colors.GREEN
        seen = last_used.strftime("%Y-%m-%d %H:%M") if last_used else "never"
        typer.secho(
            f"{name[:25]:<26} {prefix:<16} {scope:<6} {state:<10} {uses:>6}  {seen}",
            fg=colour if state != "active" else None,
        )


@token_app.command("revoke")
def token_revoke(
    identifier: Annotated[str, typer.Argument(help="Token name or id.")],
    actor: Annotated[str, typer.Option(help="Who is revoking.")] = "cli",
) -> None:
    """Revoke a token. The row is kept, flagged — an audit trail, not a delete."""
    from core.db import session_scope
    from core.pipeline.tokens import TokenError, revoke_token

    try:
        with session_scope() as session:
            record = revoke_token(session, identifier, actor=actor)
            label, prefix = record.name, record.token_prefix
    except TokenError as exc:
        _fail(str(exc))
    except Exception as exc:
        _fail(f"could not revoke the token: {exc}")

    typer.secho(f"revoked {label!r} ({prefix})", fg=typer.colors.GREEN)


def _naive(value: datetime) -> datetime:
    """SQLite returns naive datetimes even from timezone-aware columns, so
    comparisons have to be made on common ground."""
    return value.replace(tzinfo=None) if value.tzinfo is not None else value
