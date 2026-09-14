"""Authentication and scope enforcement through the real app.

These are the tests that would catch "we wrote an auth module and forgot to
attach it to a router" — which is the way this feature actually fails. Every
protected route is enumerated and checked, rather than trusting that a
dependency declared on one router covers the rest.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from api.main import create_app
from core.auth import Scope
from core.config import get_settings
from core.db import get_session
from core.models import Artifact, AuditLog, Finding, FindingLocation, Run
from core.models.base import Base
from core.models.enums import AuditAction, RunStatus
from core.pipeline.tokens import create_token
from core.vocab import Severity

# Every route that must refuse an anonymous caller, with the scope it needs.
CI_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/runs"),
    ("GET", "/api/runs/run-1"),
    ("POST", "/api/runs/run-1/gate"),
    ("GET", "/api/runs/run-1/sarif"),
]
ADMIN_ROUTES: list[tuple[str, str]] = [
    ("GET", "/api/runs/run-1/findings"),
    ("GET", "/api/runs/run-1/findings/finding-critical"),
    ("GET", "/api/settings/llm"),
    ("GET", "/api/settings/rules"),
    ("POST", "/api/runs/run-1/triage"),
]


@pytest.fixture(autouse=True)
def _auth_on(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.setenv("BARE_AUTH_REQUIRED", "true")
    # `GET /api/settings/llm` loads the live LLM config from `data_dir`, whose
    # default — `/app/data` — is the container path that exists under
    # `docker compose` and nowhere else. On a CI runner the route's
    # seed-on-first-use mkdir dies with `PermissionError: '/app'`, which has
    # nothing to do with scopes and everything to do with where the test
    # process happens to be allowed to write.
    monkeypatch.setenv("BARE_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def env() -> Iterator[tuple[TestClient, sessionmaker[Session]]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    app = create_app()

    def _override() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override
    with factory() as setup:
        _seed(setup)
        setup.commit()

    yield TestClient(app), factory
    engine.dispose()


def _seed(session: Session) -> None:
    session.add(
        Run(
            id="run-1",
            status=RunStatus.COMPLETED,
            profile="standard",
            attested_by="kyle",
            attestation_reference="SEC-1",
            attested_at=datetime.now(UTC),
        )
    )
    session.add(
        Artifact(
            id="art-1",
            run_id="run-1",
            name="installer.exe",
            path_in_tree="installer.exe",
            sha256="0" * 64,
            size_bytes=2048,
        )
    )
    session.add(
        Finding(
            id="finding-critical",
            run_id="run-1",
            rule_id="aws_secret_key",
            category="cloud_credentials",
            title="AWS secret access key",
            severity=Severity.CRITICAL.value,
            value_masked="AKIA****************",
            value_hash="a" * 64,
            status="open",
        )
    )
    session.add(
        FindingLocation(
            finding_id="finding-critical",
            run_id="run-1",
            artifact_id="art-1",
            path_in_tree="installer.exe",
            offset=4096,
        )
    )


def _mint(factory: sessionmaker[Session], name: str, scope: Scope) -> str:
    with factory() as session:
        minted = create_token(session, name=name, scope=scope)
        session.commit()
        return minted.token


def _call(client: TestClient, method: str, path: str, token: str | None = None):  # type: ignore[no-untyped-def]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.request(method, path, headers=headers, json={})


# --- the control is actually attached -------------------------------------


@pytest.mark.parametrize(("method", "path"), CI_ROUTES + ADMIN_ROUTES)
def test_every_api_route_refuses_anonymous(
    env: tuple[TestClient, sessionmaker[Session]], method: str, path: str
) -> None:
    """The failure mode this exists for: an auth module nobody attached."""
    client, _ = env
    response = _call(client, method, path)
    assert response.status_code == 401, f"{method} {path} allowed an anonymous caller"
    assert response.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.parametrize(("method", "path"), CI_ROUTES + ADMIN_ROUTES)
def test_every_api_route_refuses_an_unknown_token(
    env: tuple[TestClient, sessionmaker[Session]], method: str, path: str
) -> None:
    client, _ = env
    assert _call(client, method, path, "bare_not-a-real-token-at-all").status_code == 401


def test_health_endpoints_stay_open(env: tuple[TestClient, sessionmaker[Session]]) -> None:
    """Orchestrators probe these before any credential exists, and a liveness
    check behind auth turns a token problem into a rolling restart."""
    client, _ = env
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)


# --- scopes ---------------------------------------------------------------


@pytest.mark.parametrize(("method", "path"), CI_ROUTES)
def test_ci_token_reaches_ci_routes(
    env: tuple[TestClient, sessionmaker[Session]], method: str, path: str
) -> None:
    client, factory = env
    token = _mint(factory, f"ci-{path}", Scope.CI)
    assert _call(client, method, path, token).status_code != 401


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_ci_token_is_forbidden_from_the_findings_corpus(
    env: tuple[TestClient, sessionmaker[Session]], method: str, path: str
) -> None:
    """ADR-0019: a build agent submits and receives a verdict. It does not get
    to read the company's exposed secrets."""
    client, factory = env
    token = _mint(factory, f"ci-{path}", Scope.CI)
    response = _call(client, method, path, token)
    assert response.status_code == 403, f"{method} {path} leaked to a CI token"
    assert "scope" in response.text


@pytest.mark.parametrize(("method", "path"), ADMIN_ROUTES)
def test_admin_token_reaches_admin_routes(
    env: tuple[TestClient, sessionmaker[Session]], method: str, path: str
) -> None:
    client, factory = env
    token = _mint(factory, f"admin-{path}", Scope.ADMIN)
    response = _call(client, method, path, token)
    assert response.status_code not in (401, 403)


def test_403_is_distinct_from_401(env: tuple[TestClient, sessionmaker[Session]]) -> None:
    """'Rotate your token' and 'use a different one' are different problems."""
    client, factory = env
    ci = _mint(factory, "ci", Scope.CI)
    assert _call(client, "GET", "/api/runs/run-1/findings").status_code == 401
    assert _call(client, "GET", "/api/runs/run-1/findings", ci).status_code == 403


# --- credential handling --------------------------------------------------


def test_bare_token_without_bearer_scheme_is_accepted(
    env: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, factory = env
    token = _mint(factory, "ci", Scope.CI)
    response = client.get("/api/runs", headers={"Authorization": token})
    assert response.status_code != 401


def test_alternate_header_is_accepted(env: tuple[TestClient, sessionmaker[Session]]) -> None:
    """Some proxies strip Authorization outright."""
    client, factory = env
    token = _mint(factory, "ci", Scope.CI)
    response = client.get("/api/runs", headers={"X-Bare-Token": token})
    assert response.status_code != 401


def test_revoked_token_is_refused(env: tuple[TestClient, sessionmaker[Session]]) -> None:
    client, factory = env
    token = _mint(factory, "ci", Scope.CI)
    assert _call(client, "GET", "/api/runs", token).status_code != 401

    from core.pipeline.tokens import revoke_token

    with factory() as session:
        revoke_token(session, "ci")
        session.commit()

    assert _call(client, "GET", "/api/runs", token).status_code == 401


def test_upload_requires_a_token(env: tuple[TestClient, sessionmaker[Session]]) -> None:
    """The route that actually matters for a build pipeline."""
    client, _ = env
    response = client.post(
        "/api/runs",
        files={"file": ("installer.exe", b"MZ\x90\x00", "application/octet-stream")},
        data={"attested_by": "kyle", "attestation_reference": "SEC-1"},
    )
    assert response.status_code == 401


# --- auditing -------------------------------------------------------------


def test_rejection_is_audited_without_the_token(
    env: tuple[TestClient, sessionmaker[Session]],
) -> None:
    client, factory = env
    secret = "bare_thisIsNotARealTokenButLooksLikeOne1234"
    _call(client, "GET", "/api/runs", secret)

    with factory() as session:
        entries = session.query(AuditLog).filter_by(action=AuditAction.AUTH_FAILED).all()
        assert entries, "a rejected credential must be auditable"
        rendered = str([e.detail for e in entries])
        assert secret not in rendered
        assert "bare_thisIsNo" in rendered  # the redacted prefix, for correlation


def test_garbage_credential_is_not_recorded_as_a_token_prefix(
    env: tuple[TestClient, sessionmaker[Session]],
) -> None:
    """Only things shaped like our tokens get a prefix recorded; a random
    header value must not pollute the audit trail."""
    client, factory = env
    _call(client, "GET", "/api/runs", "hunter2")

    with factory() as session:
        entry = session.query(AuditLog).filter_by(action=AuditAction.AUTH_FAILED).first()
        assert entry is not None
        assert entry.detail.get("token_prefix") is None


# --- the escape hatch -----------------------------------------------------


def test_auth_can_be_disabled_for_local_development(
    monkeypatch: pytest.MonkeyPatch, env: tuple[TestClient, sessionmaker[Session]]
) -> None:
    client, _ = env
    monkeypatch.setenv("BARE_AUTH_REQUIRED", "false")
    get_settings.cache_clear()
    try:
        assert client.get("/api/runs").status_code == 200
    finally:
        get_settings.cache_clear()


def test_auth_is_required_by_default() -> None:
    """The default is the restrictive one. If this ever flips, a deployment
    that never set the variable silently becomes open."""
    get_settings.cache_clear()
    import os

    os.environ.pop("BARE_AUTH_REQUIRED", None)
    try:
        assert get_settings().auth_required is True
    finally:
        get_settings.cache_clear()
