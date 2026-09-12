"""Token lifecycle against the database.

:mod:`core.auth` holds the cryptography and the scope rules and knows nothing
about storage; this is the part that needs a session. The split is the same one
:mod:`core.policy` and :mod:`core.pipeline.gate` make, and for the same reason —
the security-relevant logic stays testable without a database.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.auth import TOKEN_PREFIX, Scope, generate_token, hash_token, redact
from core.models import ApiToken, AuditLog
from core.models.enums import AuditAction

log = structlog.get_logger(__name__)

BOOTSTRAP_TOKEN_NAME = "bootstrap"


class TokenError(ValueError):
    """A token could not be created or revoked as asked."""


@dataclass(frozen=True, slots=True)
class MintedToken:
    """The one and only time the plaintext exists outside the caller's hands."""

    token: str
    record_id: str
    name: str
    scope: Scope
    expires_at: datetime | None


def create_token(
    session: Session,
    *,
    name: str,
    scope: Scope = Scope.CI,
    created_by: str = "system",
    expires_in_days: int | None = None,
) -> MintedToken:
    """Mint a token, store only its hash, and return the plaintext once."""
    label = name.strip()
    if not label:
        raise TokenError("a token needs a name; an unnameable credential cannot be rotated")

    existing = session.scalars(
        select(ApiToken).where(ApiToken.name == label, ApiToken.revoked_at.is_(None))
    ).first()
    if existing is not None:
        raise TokenError(
            f"an active token named {label!r} already exists "
            f"({existing.token_prefix}); revoke it first or choose another name"
        )

    expires_at: datetime | None = None
    if expires_in_days is not None:
        if expires_in_days <= 0:
            raise TokenError("expires_in_days must be positive")
        expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)

    plaintext = generate_token()
    record = ApiToken(
        name=label,
        token_hash=hash_token(plaintext),
        token_prefix=redact(plaintext),
        scope=scope.value,
        created_by=created_by,
        expires_at=expires_at,
    )
    session.add(record)
    session.flush()

    session.add(
        AuditLog.record(
            AuditAction.TOKEN_CREATED,
            actor=created_by,
            token_id=record.id,
            token_name=label,
            token_prefix=record.token_prefix,
            scope=scope.value,
            expires_at=expires_at.isoformat() if expires_at else None,
        )
    )
    log.info("auth.token_created", name=label, scope=scope.value, prefix=record.token_prefix)
    return MintedToken(
        token=plaintext,
        record_id=record.id,
        name=label,
        scope=scope,
        expires_at=expires_at,
    )


def revoke_token(session: Session, identifier: str, *, actor: str = "system") -> ApiToken:
    """Revoke by id or by name. Revocation is a flag, never a delete."""
    key = identifier.strip()
    record = session.get(ApiToken, key)
    if record is None:
        record = session.scalars(
            select(ApiToken).where(ApiToken.name == key, ApiToken.revoked_at.is_(None))
        ).first()
    if record is None:
        # Fall back to a revoked row of the same name purely so the error can
        # say "already revoked" instead of "no such token". A name may be
        # reused after revocation, so the active lookup above must come first.
        record = session.scalars(
            select(ApiToken).where(ApiToken.name == key).order_by(ApiToken.created_at.desc())
        ).first()
    if record is None:
        raise TokenError(f"no active token matches {identifier!r}")
    if record.revoked_at is not None:
        raise TokenError(f"token {record.name!r} was already revoked at {record.revoked_at}")

    record.revoked_at = datetime.now(UTC)
    session.add(
        AuditLog.record(
            AuditAction.TOKEN_REVOKED,
            actor=actor,
            token_id=record.id,
            token_name=record.name,
            token_prefix=record.token_prefix,
        )
    )
    log.info("auth.token_revoked", name=record.name, prefix=record.token_prefix)
    return record


def list_tokens(session: Session, *, include_revoked: bool = False) -> list[ApiToken]:
    statement = select(ApiToken).order_by(ApiToken.created_at)
    if not include_revoked:
        statement = statement.where(ApiToken.revoked_at.is_(None))
    return list(session.scalars(statement).all())


def verify_token(session: Session, plaintext: str) -> ApiToken | None:
    """Resolve a presented token to its record, or ``None``.

    The lookup is a single indexed query on the hash, so an unknown token costs
    the same as a known one and the database never holds anything usable.
    Expiry and revocation are checked here rather than in the query so that the
    caller can tell "no such token" from "that token is dead" in the log
    without a second round trip.
    """
    if not plaintext:
        return None

    record = session.scalars(
        select(ApiToken).where(ApiToken.token_hash == hash_token(plaintext))
    ).first()
    if record is None:
        return None

    now = datetime.now(UTC)
    if not record.is_active(_aware(now, record)):
        log.warning(
            "auth.token_inactive",
            name=record.name,
            prefix=record.token_prefix,
            revoked=record.revoked_at is not None,
        )
        return None

    # Best-effort usage tracking. Never let a bookkeeping failure reject an
    # otherwise valid credential.
    try:
        record.last_used_at = now
        record.use_count = (record.use_count or 0) + 1
    except Exception:  # pragma: no cover - defensive
        log.warning("auth.usage_update_failed", name=record.name)
    return record


def _aware(now: datetime, record: ApiToken) -> datetime:
    """Compare like with like.

    SQLite hands back naive datetimes even for ``DateTime(timezone=True)``
    columns, so a UTC-aware ``now`` raises `TypeError` on comparison. Postgres
    does not have this problem, which is exactly why it would have been found
    in production rather than in a test.
    """
    stamp = record.expires_at
    if stamp is not None and stamp.tzinfo is None:
        return now.replace(tzinfo=None)
    return now


def tokens_exist(session: Session) -> bool:
    """Whether any API token — active, expired, or revoked — has ever existed.

    Deliberately not scoped to active tokens: a deployment that revoked its
    only token is not "unconfigured", and re-running setup would mint a second
    admin credential nobody asked for.
    """
    return session.scalars(select(ApiToken.id).limit(1)).first() is not None


def ensure_bootstrap_token(session: Session) -> MintedToken | None:
    """Mint a first admin token when authentication is on and none exists.

    Without this, enabling authentication by default would brick a fresh
    deployment: the API would require a credential that can only be created
    through the API. Callers decide how to disclose it — the dashboard's setup
    wizard shows it once in the browser; a headless operator gets it back from
    the HTTP response of whatever called this.

    Returns ``None`` when tokens already exist, which is the steady state.
    """
    if tokens_exist(session):
        return None

    minted = create_token(
        session,
        name=BOOTSTRAP_TOKEN_NAME,
        scope=Scope.ADMIN,
        created_by="bootstrap",
    )
    # The prefix, never the token. The plaintext is disclosed exactly once, to
    # whatever the caller returns it to — putting it here too would ship a live
    # admin credential to whatever aggregates these logs, where it is indexed
    # and retained outside the operator's control. That is the same mistake
    # this product exists to find in other people's binaries.
    log.warning(
        "auth.bootstrap_token_created",
        prefix=minted.token[: len(TOKEN_PREFIX) + 8],
        hint="disclosed once to the caller; not recoverable from these logs",
    )
    return minted
