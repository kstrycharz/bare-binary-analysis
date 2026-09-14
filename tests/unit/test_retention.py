"""Retained plaintext: encryption at rest, the deadline, and the purge.

§9 promised all three for years before any of them existed, and a run scanned
with retention on left real secrets in Postgres indefinitely. The cases below
are written around how that promise gets broken quietly: a value served past
its deadline because the purge job was late, a ciphertext that opens under the
wrong finding, a legacy unencrypted row served as if it were sealed, and a key
silently regenerated so everything already stored becomes garbage.
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.models import Artifact, AuditLog, Evidence, Run
from core.models.base import Base
from core.models.enums import ArtifactKind, AuditAction, RunStatus
from core.retention import (
    CIPHERTEXT_PREFIX,
    KEY_FILE,
    RetentionKeyError,
    decrypt_value,
    encrypt_value,
    generate_key,
    plaintext_available,
    purge_expired_plaintext,
    retention_deadline,
    retention_key,
)

KEY = os.urandom(32)
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
# A provably-invalid shape; never a real credential in this repository.
SECRET = "AKIAIOSFODNN7EXAMPLE"


def _seal(value: str = SECRET, *, run_id: str = "r1", value_hash: str = "h1") -> str:
    return encrypt_value(value, run_id=run_id, value_hash=value_hash, key=KEY)


# --- sealing -----------------------------------------------------------------


def test_a_value_round_trips() -> None:
    assert decrypt_value(_seal(), run_id="r1", value_hash="h1", key=KEY) == SECRET


def test_the_stored_form_does_not_contain_the_value() -> None:
    stored = _seal()
    assert stored.startswith(CIPHERTEXT_PREFIX)
    assert SECRET not in stored


def test_the_same_value_seals_differently_each_time() -> None:
    """A deterministic ciphertext would let anyone with the table see which
    findings share a secret without holding the key."""
    assert _seal() != _seal()


@pytest.mark.parametrize(
    ("run_id", "value_hash"),
    [("r2", "h1"), ("r1", "h2")],
    ids=["another run", "another value hash"],
)
def test_a_ciphertext_does_not_open_under_another_row(run_id: str, value_hash: str) -> None:
    assert decrypt_value(_seal(), run_id=run_id, value_hash=value_hash, key=KEY) is None


def test_the_wrong_key_opens_nothing() -> None:
    assert decrypt_value(_seal(), run_id="r1", value_hash="h1", key=os.urandom(32)) is None


def test_a_tampered_ciphertext_opens_nothing() -> None:
    stored = _seal()
    flipped = stored[:-3] + ("A" if stored[-3] != "A" else "B") + stored[-2:]
    assert decrypt_value(flipped, run_id="r1", value_hash="h1", key=KEY) is None


@pytest.mark.parametrize(
    "stored",
    [SECRET, f"{CIPHERTEXT_PREFIX}deadbeef:not-base64!!", f"{CIPHERTEXT_PREFIX}"],
    ids=["legacy unencrypted row", "garbage body", "empty body"],
)
def test_anything_that_is_not_a_valid_ciphertext_is_absent(stored: str) -> None:
    """Fail closed. Serving a legacy plaintext row as-is would make the
    encryption optional in practice."""
    assert decrypt_value(stored, run_id="r1", value_hash="h1", key=KEY) is None


# --- the key -----------------------------------------------------------------


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    return Settings(data_dir=tmp_path, **overrides)


def test_a_configured_key_is_used(tmp_path: Path) -> None:
    configured = generate_key()
    key = retention_key(_settings(tmp_path, retention_key=configured))
    assert len(key) == 32
    assert not (tmp_path / KEY_FILE).exists()


@pytest.mark.parametrize("bad", ["too-short", "!!!!not base64!!!!", "AAAA"])
def test_an_unusable_configured_key_is_an_error_not_a_fallback(tmp_path: Path, bad: str) -> None:
    with pytest.raises(RetentionKeyError):
        retention_key(_settings(tmp_path, retention_key=bad))


def test_without_a_configured_key_one_is_generated_once(tmp_path: Path) -> None:
    first = retention_key(_settings(tmp_path))
    path = tmp_path / KEY_FILE
    assert path.is_file()
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert retention_key(_settings(tmp_path)) == first


def test_an_existing_key_file_is_read_and_never_replaced(tmp_path: Path) -> None:
    """The API and a worker share the file; whichever starts second must use
    the first one's key, or values sealed by one never open in the other."""
    existing = generate_key()
    (tmp_path / KEY_FILE).write_text(existing + "\n", encoding="ascii")
    key = retention_key(_settings(tmp_path))
    assert (tmp_path / KEY_FILE).read_text(encoding="ascii").strip() == existing
    assert (
        decrypt_value(
            encrypt_value(SECRET, run_id="r", value_hash="h", key=key),
            run_id="r",
            value_hash="h",
            key=retention_key(_settings(tmp_path)),
        )
        == SECRET
    )


def test_a_corrupt_key_file_is_an_error_and_is_left_alone(tmp_path: Path) -> None:
    (tmp_path / KEY_FILE).write_text("corrupt\n", encoding="ascii")
    with pytest.raises(RetentionKeyError):
        retention_key(_settings(tmp_path))
    assert (tmp_path / KEY_FILE).read_text(encoding="ascii") == "corrupt\n"


# --- the deadline --------------------------------------------------------------


def test_the_deadline_is_the_configured_ttl(tmp_path: Path) -> None:
    assert retention_deadline(NOW, _settings(tmp_path, plaintext_ttl_hours=24)) == NOW + timedelta(
        hours=24
    )


def test_a_zero_ttl_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        _settings(tmp_path, plaintext_ttl_hours=0)


def _retaining(**overrides: Any) -> Run:
    fields: dict[str, Any] = {
        "id": "r1",
        "status": RunStatus.COMPLETED,
        "profile": "standard",
        "attested_by": "kyle",
        "attestation_reference": "SEC-1",
        "attested_at": NOW - timedelta(days=1),
        "retain_plaintext": True,
        "plaintext_expires_at": NOW + timedelta(hours=1),
    }
    fields.update(overrides)
    return Run(**fields)


@pytest.mark.parametrize(
    ("run", "available"),
    [
        (_retaining(), True),
        (_retaining(plaintext_expires_at=NOW), False),
        (_retaining(plaintext_expires_at=NOW - timedelta(seconds=1)), False),
        (_retaining(plaintext_purged_at=NOW - timedelta(days=1)), False),
        (_retaining(retain_plaintext=False), False),
        (_retaining(plaintext_expires_at=None), False),
        # SQLite returns timestamps naive; they are UTC.
        (_retaining(plaintext_expires_at=(NOW + timedelta(hours=1)).replace(tzinfo=None)), True),
        (None, False),
    ],
    ids=[
        "retaining, before the deadline",
        "at the deadline",
        "after the deadline",
        "purged",
        "never retained",
        "retaining with no deadline fails closed",
        "naive timestamp",
        "no run",
    ],
)
def test_plaintext_availability(run: Run | None, available: bool) -> None:
    assert plaintext_available(run, NOW) is available


# --- the purge -----------------------------------------------------------------


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        yield active


def _add_run(session: Session, run_id: str, **overrides: Any) -> None:
    session.add(_retaining(id=run_id, **overrides))
    session.add(
        Artifact(
            id=f"{run_id}-a",
            run_id=run_id,
            name="app.exe",
            path_in_tree="app.exe",
            depth=0,
            sha256="0" * 64,
            size_bytes=1,
            kind=ArtifactKind.PE,
        )
    )
    session.flush()
    for index in range(2):
        session.add(
            Evidence(
                run_id=run_id,
                artifact_id=f"{run_id}-a",
                analyzer="static",
                rule_id="aws-access-key-id",
                value_hash=f"h{index}",
                value_masked="AKIA••••",
                value_plaintext=_seal(run_id=run_id, value_hash=f"h{index}"),
                offset=index,
            )
        )
    session.flush()


def _stored(session: Session, run_id: str) -> list[str | None]:
    return list(
        session.scalars(select(Evidence.value_plaintext).where(Evidence.run_id == run_id)).all()
    )


def test_expired_values_are_deleted_and_live_ones_kept(session: Session) -> None:
    _add_run(session, "expired", plaintext_expires_at=NOW - timedelta(minutes=1))
    _add_run(session, "live", plaintext_expires_at=NOW + timedelta(days=1))

    report = purge_expired_plaintext(session, NOW)

    assert report.runs == ("expired",)
    assert report.values == 2
    assert _stored(session, "expired") == [None, None]
    assert all(value is not None for value in _stored(session, "live"))
    assert session.get(Run, "expired").plaintext_purged_at is not None  # type: ignore[union-attr]
    assert session.get(Run, "live").plaintext_purged_at is None  # type: ignore[union-attr]


def test_a_purge_is_audited_with_its_count(session: Session) -> None:
    _add_run(session, "expired", plaintext_expires_at=NOW - timedelta(minutes=1))
    purge_expired_plaintext(session, NOW)

    (entry,) = session.scalars(
        select(AuditLog).where(AuditLog.action == AuditAction.PLAINTEXT_PURGED)
    ).all()
    assert entry.run_id == "expired"
    assert entry.detail["values_purged"] == 2


def test_purging_twice_does_nothing_the_second_time(session: Session) -> None:
    _add_run(session, "expired", plaintext_expires_at=NOW - timedelta(minutes=1))
    purge_expired_plaintext(session, NOW)
    again = purge_expired_plaintext(session, NOW + timedelta(hours=1))
    assert again.runs == () and again.values == 0


def test_a_retaining_run_with_no_deadline_is_purged(session: Session) -> None:
    """A row that somehow escaped getting a deadline must not become the one
    run that keeps its secrets for ever."""
    _add_run(session, "undated", plaintext_expires_at=None)
    assert purge_expired_plaintext(session, NOW).runs == ("undated",)


# --- where values are written ------------------------------------------------------


def _payload() -> dict[str, Any]:
    return {
        "files": [
            {
                "relative_path": "app.exe",
                "matches": [
                    {
                        "rule_id": "aws-access-key-id",
                        "value_hash": "h1",
                        "value_masked": "AKIA••••",
                        "value_plaintext": SECRET,
                    }
                ],
            }
        ]
    }


@pytest.fixture
def scan_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    monkeypatch.setattr("core.pipeline.scan.retention_key", lambda: KEY)
    return KEY


def _evidence_for(run: Run) -> Evidence:
    from core.pipeline.scan import _to_evidence

    root = Artifact(id="root", run_id=run.id, name="app.exe", path_in_tree="app.exe")
    (row,) = _to_evidence(run, _payload(), {"app.exe": "root"}, root)
    return row


def test_the_scan_stores_ciphertext_never_the_value(scan_key: bytes) -> None:
    run = _retaining(plaintext_expires_at=datetime.now(UTC) + timedelta(days=1))
    row = _evidence_for(run)
    assert row.value_plaintext is not None
    assert SECRET not in row.value_plaintext
    assert decrypt_value(row.value_plaintext, run_id="r1", value_hash="h1", key=scan_key) == SECRET


def test_a_run_whose_retention_lapsed_while_queued_stores_nothing(scan_key: bytes) -> None:
    run = _retaining(plaintext_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    assert _evidence_for(run).value_plaintext is None


def test_a_run_that_did_not_opt_in_stores_nothing_even_if_the_analyzer_sent_it(
    scan_key: bytes,
) -> None:
    run = _retaining(retain_plaintext=False)
    assert _evidence_for(run).value_plaintext is None


# --- where the deadline is set ------------------------------------------------------


@pytest.mark.parametrize("retain", [True, False])
def test_ingest_sets_the_deadline_from_upload_time(
    session: Session, monkeypatch: pytest.MonkeyPatch, retain: bool
) -> None:
    from core.pipeline.ingest import ingest_artifact

    class _Store:
        def put_stream(self, stream: Any, name: str) -> SimpleNamespace:
            return SimpleNamespace(key="k", sha256="0" * 64, size_bytes=3)

    monkeypatch.setattr("core.pipeline.ingest.get_object_store", lambda: _Store())
    result = ingest_artifact(
        session,
        io.BytesIO(b"abc"),
        filename="app.exe",
        attested_by="kyle",
        attestation_reference="SEC-12345",
        retain_plaintext=retain,
    )
    run = result.run
    if not retain:
        assert run.plaintext_expires_at is None
        return
    assert run.plaintext_expires_at is not None
    assert run.plaintext_expires_at - run.attested_at == timedelta(hours=168)
