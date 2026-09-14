"""Keeping analyzer logs: redaction, caps, the read path, and the endpoint (bounty: analyzer-logs).

The retained log is untrusted output derived from a customer's binary, and it
runs against real secrets because the analyzer is a tool that reads secrets.
The tests here exist for the things the PR has to be able to claim:

- the masking demonstrably applies (against the **real** shipped rule pack,
  not a toy one — the pack is the detector and a fake pack proves nothing),
- a chatty analyzer cannot grow the stored object without bound, and
- the endpoint serves plain text, is scoped like the findings corpus, and
  404s with a reason rather than lying with an empty 200.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import api.routers.runs as runs_router
import core.db as db_module
from api.main import create_app
from core.auth import Scope
from core.models import Run, RunStage
from core.models.base import Base
from core.models.enums import RunStatus, StageStatus
from core.pipeline.logs import (
    MAX_STORED_LOG_BYTES,
    redact_log_text,
    render_stage_log,
    stage_log_key,
    store_stage_log,
)
from core.pipeline.tokens import create_token
from core.rules import load_rule_pack

RULES_DIR = Path(__file__).resolve().parents[2] / "detections"
NOW = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)

# Provably-invalid shapes assembled so no full key literal exists in the tree
# (§9: fixtures never carry commit-shaped secrets; gitleaks runs in CI). These
# still match the real shipped pack, which is the point: the pack is the
# detector the redaction guarantee rests on.
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLZ"
AWS_SECRET = "wJalrXUtnFEMI" + "K7MDENGbPxRfiCYEXAMPLEQ"  # 13+27: the 40 the rule wants


def test_pack() -> Any:
    return load_rule_pack(RULES_DIR)


class _FakeBucket:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803
        self.objects[Key] = Body

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        class _Body:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": _Body(self.objects[Key])}


class _FakeStore:
    def __init__(self) -> None:
        self.bucket_obj = _FakeBucket()

    def ensure_bucket(self) -> None:
        pass

    @property
    def bucket(self) -> str:
        return "bare-artifacts"

    @property
    def client(self) -> _FakeBucket:
        return self.bucket_obj


class TestRedaction:
    def test_a_credential_echoed_in_a_log_is_masked(self) -> None:
        pack = test_pack()
        text = f"opening config: aws_access_key_id={AWS_KEY} secret={AWS_SECRET}\n"
        out = redact_log_text(text, pack=pack)
        assert AWS_KEY not in out
        assert AWS_SECRET not in out
        assert "AKIA" in out  # recognisable shape survives; the value does not

    def test_benign_log_text_is_untouched(self) -> None:
        pack = test_pack()
        text = "scanning 412 files\nmatched rule: none\n"
        assert redact_log_text(text, pack=pack) == text

    def test_redaction_is_deterministic(self) -> None:
        pack = test_pack()
        text = f"both: {AWS_KEY} {AWS_SECRET} and again {AWS_KEY}\n"
        a, b = redact_log_text(text, pack=pack), redact_log_text(text, pack=pack)
        assert a == b


class TestRender:
    def test_both_streams_appear_as_text_sections(self) -> None:
        pack = test_pack()
        document, truncated = render_stage_log(b"out line\n", b"err line\n", pack=pack)
        assert not truncated
        assert "--- stdout ---" in document and "out line" in document
        assert "--- stderr ---" in document and "err line" in document

    def test_a_chatty_analyzer_cannot_grow_the_document_without_bound(self) -> None:
        pack = test_pack()
        chatty = (b"x" * 4096 + b"\n") * (MAX_STORED_LOG_BYTES // 4096 * 3)
        document, truncated = render_stage_log(chatty, b"", pack=pack)
        assert truncated
        assert "[bare: stored log truncated]" in document
        # Two streams at the cap, plus the fixed section headings: bounded by
        # 2x the cap plus a small constant, not by what the analyzer printed.
        assert len(document.encode("utf-8")) <= 2 * MAX_STORED_LOG_BYTES + 4096

    def test_the_driver_cap_note_is_reported_as_truncated(self) -> None:
        pack = test_pack()
        document, truncated = render_stage_log(b"[bare: log truncated]\n", b"", pack=pack)
        assert truncated and "log truncated" in document

    def test_undecodable_bytes_survive_as_replacement_text(self) -> None:
        """Analyzer output is untrusted; a byte that is not valid UTF-8 must
        not fail the retention, only read oddly."""
        pack = test_pack()
        document, _ = render_stage_log(b"caf\xe9\xff\xfe bytes\n", b"", pack=pack)
        assert "bytes" in document


class TestStore:
    def test_roundtrip_and_key_shape(self) -> None:
        pack = test_pack()
        store = _FakeStore()
        key, size, truncated = store_stage_log(
            store,  # type: ignore[arg-type]
            run_id="run-1",
            stage_id="stage-1",
            stdout=f"key={AWS_KEY}\n".encode(),
            stderr=b"",
            pack=pack,
        )
        assert key == stage_log_key("run-1", "stage-1")
        assert key.startswith("logs/run-1/")
        assert size == len(store.bucket_obj.objects[key])
        assert not truncated
        assert AWS_KEY not in store.bucket_obj.objects[key].decode()

    def test_a_bucket_failure_degrades_to_no_log_rather_than_raising(self) -> None:
        """ADR-0008: a successful scan does not go red over its logs. The
        after-dinner mint failing is not the dinner failing."""

        class _Broken(_FakeStore):
            @property
            def client(self) -> Any:
                raise RuntimeError("minio unreachable")

        pack = test_pack()
        key, size, truncated = store_stage_log(
            _Broken(),  # type: ignore[arg-type]
            run_id="run-1",
            stage_id="stage-1",
            stdout=b"",
            stderr=b"",
            pack=pack,
        )
        assert key is None and size == 0 and not truncated


# --- the endpoint ----------------------------------------------------------


@pytest.fixture
def app_client(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[TestClient, sessionmaker[Session], _FakeStore]]:
    """Real app, throwaway SQLite, and the bucket faked at the seam.

    The store is patched where the router resolves it — a scan writing logs
    and an operator reading them must go through the same handle, and this
    test proves the read path against the bytes the write path stored.
    """
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory: sessionmaker[Session] = sessionmaker(bind=engine, expire_on_commit=False)
    db_module.get_engine.cache_clear()
    db_module.get_sessionmaker.cache_clear()
    monkeypatch.setattr(db_module, "get_engine", lambda: engine)

    store = _FakeStore()
    monkeypatch.setattr(runs_router, "get_object_store", lambda: store)

    app = create_app()

    def _override() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[db_module.get_session] = _override
    with factory() as setup:
        setup.add(
            Run(
                id="run-logs",
                status=RunStatus.COMPLETED,
                attested_by="tester",
                attestation_reference="t",
                attested_at=NOW,
            )
        )
        setup.add(
            RunStage(
                id="stage-static",
                run_id="run-logs",
                analyzer="static",
                status=StageStatus.FAILED,
                log_key="logs/run-logs/stage-static.txt",
                log_bytes=42,
                log_truncated=False,
            )
        )
        setup.add(
            RunStage(
                id="stage-no-log",
                run_id="run-logs",
                analyzer="unpack",
                status=StageStatus.COMPLETED,
            )
        )
        setup.commit()
        pack = load_rule_pack(RULES_DIR)
        document, _ = render_stage_log(f"loading {AWS_KEY}\n".encode(), b"boom\n", pack=pack)
        admin = create_token(setup, name="admin-logs", scope=Scope.ADMIN).token
        ci = create_token(setup, name="ci-logs", scope=Scope.CI).token
        setup.commit()
    store.bucket_obj.objects["logs/run-logs/stage-static.txt"] = document.encode("utf-8")

    client = TestClient(app)
    client.headers["authorization"] = f"Bearer {admin}"
    yield client, factory, store, ci
    db_module.get_sessionmaker.cache_clear()
    engine.dispose()


class TestEndpoint:
    def test_serves_plain_text_with_neutering_headers(self, app_client: Any) -> None:
        client, _, _, _ci = app_client
        response = client.get("/api/runs/run-logs/stages/stage-static/logs")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "sandbox" in response.headers["content-security-policy"]
        # The stored document is already masked; the endpoint must not re-expose.
        assert AWS_KEY not in response.text
        assert "boom" in response.text

    def test_html_never_wins_no_matter_what_the_analyzer_printed(self, app_client: Any) -> None:
        """A log is untrusted output; nothing on this path parses it."""
        client, _, store, _ci = app_client
        store.bucket_obj.objects["logs/run-logs/stage-static.txt"] = (
            b"<script>alert(1)</script> stdout\n"
        )
        text = client.get("/api/runs/run-logs/stages/stage-static/logs").text
        assert "<script>" in text  # served as characters, inert by content-type
        # ...and it renders in React as escaped text nodes, never markup.

    def test_unknown_stage_is_404(self, app_client: Any) -> None:
        client, _, _, _ci = app_client
        assert client.get("/api/runs/run-logs/stages/nope/logs").status_code == 404

    def test_stage_from_another_run_is_404_not_a_leak(self, app_client: Any) -> None:
        client, _, _, _ci = app_client
        assert client.get("/api/runs/other-run/stages/stage-static/logs").status_code == 404

    def test_no_log_retained_is_404_with_a_reason(self, app_client: Any) -> None:
        """An empty 200 would read as 'the analyzer printed nothing', which is
        a different fact and a false one."""
        client, _, _, _ci = app_client
        response = client.get("/api/runs/run-logs/stages/stage-no-log/logs")
        assert response.status_code == 404
        assert "no log retained" in response.json()["detail"]

    def test_unreadable_object_is_502_not_a_200_with_garbage(self, app_client: Any) -> None:
        client, _, store, _ci = app_client
        del store.bucket_obj.objects["logs/run-logs/stage-static.txt"]
        assert client.get("/api/runs/run-logs/stages/stage-static/logs").status_code == 502

    def test_a_ci_token_cannot_read_logs(self, app_client: Any) -> None:
        """Same gate as the findings corpus: log text is masked secret
        context, and a build agent does not read the company's secrets."""
        client, _, _, ci = app_client
        response = client.get(
            "/api/runs/run-logs/stages/stage-static/logs",
            headers={"authorization": f"Bearer {ci}"},
        )
        assert response.status_code == 403
