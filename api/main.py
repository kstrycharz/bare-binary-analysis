"""BARE API application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from api.routers import findings, gate, health, runs, settings, setup
from core.config import BARE_VERSION, get_settings
from core.logging import configure_logging

log = structlog.get_logger(__name__)

DESCRIPTION = """
BARE analyses the artifacts you are about to ship — installers,
executables, firmware images — for exposed secrets, sensitive data, and
unintended IP disclosure.

Every artifact submitted requires an authorization attestation. The operator
must own, or be contractually authorized to test, what they upload.
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app_settings = get_settings()
    configure_logging(level=app_settings.log_level, json_output=app_settings.log_json)
    log.info(
        "api.startup",
        version=BARE_VERSION,
        environment=app_settings.environment,
        sandbox_driver=app_settings.sandbox_driver,
        egress_policy=app_settings.egress_policy,
        air_gapped=app_settings.air_gapped,
    )

    # Migrate on start-up so `make dev` works from a clean clone and an
    # upgraded deployment cannot serve against a schema older than its code.
    # A failure here is fatal on purpose: the previous behaviour logged a
    # warning and carried on, which meant a missing column surfaced later as a
    # 500 on an ordinary request rather than as a refusal to start.
    from core.db import upgrade_schema

    upgrade_schema()
    log.info("api.schema_current")

    _announce_auth(app_settings.auth_required)

    yield
    log.info("api.shutdown")


def _announce_auth(auth_required: bool) -> None:
    """Say plainly whether the API is protected, and whether it is waiting to
    be set up.

    Minting the first admin token is not done here. It used to be — a console
    banner, printed once, unrecoverable if missed — and the failure mode was
    exactly that: two processes racing to start first meant only one of them
    ever showed it, and it was easy to lose in scrollback before anyone read
    it. `POST /api/setup/bootstrap` (``api/routers/setup.py``) does the same
    one-shot mint on request instead, from the dashboard's setup wizard or a
    single deliberate `curl`, where the operator is already looking.
    """
    if not auth_required:
        # Loud on purpose. This is the configuration where anyone who can reach
        # the port can read every finding.
        log.warning(
            "api.auth_disabled",
            detail=(
                "BARE_AUTH_REQUIRED is false: the API accepts unauthenticated "
                "requests. Acceptable only for a local single-user stack."
            ),
        )
        return

    from core.db import session_scope
    from core.pipeline.tokens import tokens_exist

    try:
        with session_scope() as session:
            exists = tokens_exist(session)
    except Exception as exc:
        log.warning("api.auth_status_check_failed", error=str(exc))
        return

    if exists:
        log.info("api.auth_enabled")
    else:
        log.info(
            "api.auth_enabled_awaiting_setup",
            detail="no API tokens exist yet; open the dashboard or POST /api/setup/bootstrap",
        )


def create_app() -> FastAPI:
    app = FastAPI(
        title="BARE",
        description=DESCRIPTION,
        version=BARE_VERSION,
        lifespan=lifespan,
    )
    # CORS is deliberately absent: the dashboard is served same-origin in the
    # reference deployment, and a findings page — a list of a company's exposed
    # secrets — is the last thing that should be reachable cross-origin.
    app.include_router(health.router)
    app.include_router(setup.router)
    app.include_router(runs.router)
    app.include_router(findings.router)
    app.include_router(gate.router)
    app.include_router(settings.router)
    return app


app = create_app()
