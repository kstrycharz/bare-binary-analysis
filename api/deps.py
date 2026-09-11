"""Request-scoped dependencies: authentication and scope enforcement.

The posture here is fail-closed. If authentication is enabled and anything
about the credential is wrong — absent, malformed, unknown, revoked, expired,
or insufficiently scoped — the request is refused. There is no path that
degrades to "allow" on error, because the one thing worse than an API with no
authentication is an API that appears to have some.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

import structlog
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from core.auth import Scope, looks_like_token, parse_bearer, redact
from core.config import get_settings
from core.db import get_session
from core.models import AuditLog
from core.models.enums import AuditAction
from core.pipeline.tokens import verify_token

log = structlog.get_logger(__name__)

# Returned on every rejection. RFC 6750's scheme name, so a client library
# knows what kind of credential to present.
_AUTH_HEADER = {"WWW-Authenticate": "Bearer"}


@dataclass(frozen=True, slots=True)
class Caller:
    """Who is making this request.

    Present even when authentication is disabled, so route code never has to
    branch on whether auth is on — it always has a caller to attribute an
    action to in the audit log.
    """

    token_id: str | None
    name: str
    scope: Scope
    authenticated: bool

    @property
    def actor(self) -> str:
        """The audit-log actor string."""
        return self.name if self.authenticated else f"unauthenticated:{self.name}"


ANONYMOUS = Caller(token_id=None, name="anonymous", scope=Scope.ADMIN, authenticated=False)
"""Used only when authentication is switched off. Scoped ADMIN deliberately:
with the control disabled there is no boundary to pretend to enforce, and a
half-enforced one would give false confidence."""


def _reject(
    session: Session,
    request: Request,
    reason: str,
    presented: str | None,
    *,
    code: int = status.HTTP_401_UNAUTHORIZED,
    detail: str = "a valid API token is required",
) -> None:
    """Record the failure, then refuse.

    A burst of these is the first visible sign of someone probing the gate, so
    it goes in the audit log rather than only the request log. The token itself
    is never recorded — only its redacted prefix, and only when it had the
    right shape to begin with.
    """
    prefix = redact(presented) if presented and looks_like_token(presented) else None
    try:
        session.add(
            AuditLog.record(
                AuditAction.AUTH_FAILED,
                actor="unauthenticated",
                reason=reason,
                path=request.url.path,
                method=request.method,
                token_prefix=prefix,
                client=request.client.host if request.client else None,
            )
        )
        session.commit()
    except Exception:  # pragma: no cover - auditing must never mask the refusal
        session.rollback()
        log.warning("auth.audit_write_failed", reason=reason)

    log.warning("auth.rejected", reason=reason, path=request.url.path, token=prefix)
    raise HTTPException(code, detail, headers=_AUTH_HEADER)


def get_caller(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    authorization: Annotated[str | None, Header()] = None,
    x_bare_token: Annotated[str | None, Header()] = None,
) -> Caller:
    """Resolve and validate the caller's credential.

    ``X-Bare-Token`` is accepted alongside ``Authorization`` because some
    CI systems and proxies rewrite or strip the standard header, and a gate
    that cannot be called is a gate that gets removed from the pipeline.
    """
    settings = get_settings()
    if not settings.auth_required:
        return ANONYMOUS

    presented = parse_bearer(authorization) or (
        x_bare_token.strip() if x_bare_token else None
    )
    if not presented:
        _reject(session, request, "no credential presented", None)

    record = verify_token(session, presented)
    if record is None:
        _reject(session, request, "unknown, revoked, or expired token", presented)

    # `verify_token` bumped last_used_at; persist it on the read path, where
    # nothing else will commit.
    try:
        session.commit()
    except Exception:  # pragma: no cover - defensive
        session.rollback()

    try:
        scope = Scope(record.scope)
    except ValueError:
        # A scope string the code no longer understands is a downgrade, not an
        # upgrade: treat it as the least privileged thing we know.
        log.warning("auth.unknown_scope", scope=record.scope, name=record.name)
        scope = Scope.CI

    return Caller(token_id=record.id, name=record.name, scope=scope, authenticated=True)


CallerDep = Annotated[Caller, Depends(get_caller)]


def require_scope(required: Scope):  # type: ignore[no-untyped-def]
    """Dependency factory enforcing a minimum scope.

    Used as ``Depends(require_scope(Scope.ADMIN))`` on the routes that read the
    findings corpus. A CI token reaching one of those is a 403, not a 401: the
    credential is valid, the action is not permitted, and telling the two apart
    is the difference between "rotate your token" and "you are using the wrong
    one".
    """

    def dependency(request: Request, caller: CallerDep) -> Caller:
        if not caller.scope.satisfies(required):
            log.warning(
                "auth.scope_denied",
                name=caller.name,
                has=caller.scope.value,
                needs=required.value,
                path=request.url.path,
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"this token has scope '{caller.scope.value}'; "
                f"'{required.value}' is required for this endpoint",
                headers=_AUTH_HEADER,
            )
        return caller

    return dependency


AdminDep = Annotated[Caller, Depends(require_scope(Scope.ADMIN))]
