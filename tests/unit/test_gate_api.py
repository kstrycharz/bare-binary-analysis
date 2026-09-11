"""The gate and SARIF endpoints, exercised through the real app.

A TestClient against in-memory SQLite, not a mocked router. This is the layer
where a wrong status code or a dropped field turns into a CI client that
misreports a verdict, and neither failure is visible from a unit test of the
functions underneath.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from api.main import create_app
from core.auth import Scope
from core.db import get_session
from core.models import Artifact, Finding, FindingLocation, Run
from core.models.base import Base
from core.models.enums import RunStatus
from core.pipeline.tokens import create_token
from core.vocab import Severity

POLICY_BLOCKING_ALL = """
version: 1
name: strict
block:
  severity_at_or_above: high
baseline:
  mode: all
"""


@pytest.fixture
def client() -> Iterator[TestClient]:
    # StaticPool keeps every session on the SAME in-memory database. Without it
    # each connection gets its own empty one and every query fails with
    # "no such table", which reads like a broken router rather than a fixture.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    app = create_app()

    def _session_override() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _session_override

    with factory() as setup:
        _seed(setup)
        # The API requires a token by default, so these tests carry a real one.
        # A CI-scoped token is what a build agent would present, and it is
        # exactly the scope the gate and SARIF endpoints are meant to accept.
        token = create_token(setup, name="gate-tests", scope=Scope.CI).token
        setup.commit()

    # Deliberately not entered as a context manager: the app lifespan tries to
    # bootstrap a real Postgres schema, which a unit test neither has nor needs.
    yield TestClient(app, headers={"Authorization": f"Bearer {token}"})
    engine.dispose()


def _seed(session: Session) -> None:
    run = Run(
        id="run-1",
        status=RunStatus.COMPLETED,
        profile="standard",
        attested_by="kyle",
        attestation_reference="SEC-1",
        attested_at=datetime.now(UTC),
    )
    session.add(run)
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
            cwe="CWE-798",
            remediation_md="Rotate the key and remove it from the build.",
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


def test_gate_blocks_and_reports_its_exit_code(client: TestClient) -> None:
    response = client.post("/api/runs/run-1/gate", json={})
    assert response.status_code == 200

    payload = response.json()
    assert payload["decision"] == "blocked"
    assert payload["exit_code"] == 1
    assert payload["run_id"] == "run-1"
    assert payload["violations"][0]["rule_id"] == "aws_secret_key"
    assert payload["violations"][0]["artifact_path"] == "installer.exe"


def test_gate_honours_a_supplied_policy(client: TestClient) -> None:
    response = client.post(
        "/api/runs/run-1/gate", json={"policy_yaml": POLICY_BLOCKING_ALL}
    )
    assert response.status_code == 200
    assert response.json()["policy_name"] == "strict"


def test_gate_passes_when_the_policy_floor_is_lifted(client: TestClient) -> None:
    lenient = "version: 1\nname: lenient\nblock:\n  severity_at_or_above: none\n"
    payload = client.post("/api/runs/run-1/gate", json={"policy_yaml": lenient}).json()
    assert payload["decision"] == "pass"
    assert payload["exit_code"] == 0


def test_a_live_waiver_unblocks_through_the_api(client: TestClient) -> None:
    waivers = (
        "waivers:\n"
        "  - finding_id: finding-critical\n"
        "    reason: vendor sample key, confirmed inert\n"
        "    owner: kyle@example.com\n"
        "    expires: 2099-01-01\n"
    )
    payload = client.post("/api/runs/run-1/gate", json={"waivers_yaml": waivers}).json()
    assert payload["decision"] == "pass"
    assert payload["waived"][0]["owner"] == "kyle@example.com"


def test_malformed_policy_is_422_not_a_silent_pass(client: TestClient) -> None:
    """A typo in a policy must fail loudly. A gate that falls back to a
    permissive default on a bad file is worse than no gate."""
    response = client.post(
        "/api/runs/run-1/gate",
        json={"policy_yaml": "version: 1\nblock:\n  severity_at_or_above: catastrophic\n"},
    )
    assert response.status_code == 422
    assert "catastrophic" in response.text


def test_malformed_waiver_is_422(client: TestClient) -> None:
    response = client.post(
        "/api/runs/run-1/gate",
        json={"waivers_yaml": "waivers:\n  - finding_id: x\n    reason: r\n    owner: o\n"},
    )
    assert response.status_code == 422
    assert "expires" in response.text


def test_gating_an_unknown_run_is_409(client: TestClient) -> None:
    assert client.post("/api/runs/nope/gate", json={}).status_code == 409


def test_sarif_endpoint_returns_a_valid_document(client: TestClient) -> None:
    response = client.get("/api/runs/run-1/sarif")
    assert response.status_code == 200

    document = response.json()
    assert document["version"] == "2.1.0"
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "aws_secret_key"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["byteOffset"] == 4096
    assert result["partialFingerprints"]["bareFindingId"] == "finding-critical"


def test_sarif_carries_no_plaintext(client: TestClient) -> None:
    assert "AKIAIOSFODNN7EXAMPLE" not in client.get("/api/runs/run-1/sarif").text


def test_sarif_for_an_unknown_run_is_404(client: TestClient) -> None:
    assert client.get("/api/runs/nope/sarif").status_code == 404


def test_pdf_report_is_a_real_pdf(client: TestClient) -> None:
    response = client.get("/api/runs/run-1/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert response.content.rstrip().endswith(b"%%EOF")
    assert "attachment" in response.headers.get("content-disposition", "")


def test_pdf_report_is_deterministic(client: TestClient) -> None:
    """A release record whose bytes change between renderings cannot be
    hashed, signed, or treated as an audit artifact."""
    first = client.get("/api/runs/run-1/report.pdf").content
    second = client.get("/api/runs/run-1/report.pdf").content
    assert first == second


def test_pdf_report_carries_no_plaintext(client: TestClient) -> None:
    """A PDF is emailed, archived and printed. It is the last place a
    credential should be legible."""
    body = client.get("/api/runs/run-1/report.pdf").content
    assert b"AKIAIOSFODNN7EXAMPLE" not in body


def test_pdf_report_for_an_unknown_run_is_404(client: TestClient) -> None:
    assert client.get("/api/runs/nope/report.pdf").status_code == 404
