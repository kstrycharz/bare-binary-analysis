"""Retained secret values: encrypted at rest, expired, and purged.

A run can opt into keeping the real value behind each finding, so a human can
go and rotate the credential. CLAUDE.md §9 attaches three conditions to that,
and this module is all three.

**Encrypted at rest.** AES-256-GCM with a random nonce per value. The associated
data binds each ciphertext to its run and value hash, so a value copied onto
another evidence row — by a bug, or by someone with write access to the table —
fails authentication instead of revealing under the wrong finding. The threat
this answers is the database leaving without the application: a backup, a
dump, a replica, a support bundle. The key lives outside Postgres for exactly
that reason (ADR-0032).

**A TTL.** Every retaining run carries ``plaintext_expires_at``, set at ingest.
It is enforced where values are *read*, not only where they are deleted, so a
purge job that is late, wedged, or not running cannot extend it.

**Auto-purge.** A beat task nulls expired values and audits how many, so the
database stops holding ciphertext that nobody may read any more.

Everything fails closed. A value that does not decrypt — wrong key, tampered,
or a legacy row written unencrypted before this module existed — is treated as
absent, never served as its stored text.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from core.config import Settings, get_settings
from core.models import AuditLog, Evidence, Run
from core.models.enums import AuditAction

KEY_FILE = "retention.key"
KEY_BYTES = 32
NONCE_BYTES = 12
CIPHERTEXT_PREFIX = "bare:v1:"


class RetentionKeyError(RuntimeError):
    """The configured key is unusable.

    Raised rather than quietly generating a replacement: a new key makes every
    value already stored unreadable, and an operator should find that out from
    an error, not from an empty reveal panel.
    """


# --- key ---------------------------------------------------------------------


def generate_key() -> str:
    """A new key, in the form ``BARE_RETENTION_KEY`` and the key file hold."""
    return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def retention_key(settings: Settings | None = None) -> bytes:
    """The key: ``BARE_RETENTION_KEY`` if set, else ``<data_dir>/retention.key``,
    created on first use.

    The file lives on the volume the API and both worker lanes already share,
    which is what lets a value sealed by a worker be opened by the API. It is
    not in Postgres, so a database backup alone does not carry it.
    """
    settings = settings or get_settings()
    return _load_key(settings.retention_key, str(settings.data_dir))


@lru_cache(maxsize=4)
def _load_key(configured: str, data_dir: str) -> bytes:
    if configured.strip():
        return _decode_key(configured, "BARE_RETENTION_KEY")
    path = Path(data_dir) / KEY_FILE
    if not path.is_file():
        _create_key_file(path)
    return _decode_key(path.read_text(encoding="ascii"), str(path))


def _create_key_file(path: Path) -> None:
    """Create the key file exactly once, even with the API and a worker racing.

    Written to a private temporary file and then hard-linked into place, which
    fails if the target exists: a process can never read a half-written key,
    and the loser of the race simply reads the winner's.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{KEY_FILE}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(generate_key() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(FileExistsError):
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _decode_key(text: str, source: str) -> bytes:
    try:
        key = base64.b64decode(text.strip().encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise RetentionKeyError(f"{source} is not a base64-encoded key") from None
    if len(key) != KEY_BYTES:
        raise RetentionKeyError(f"{source} must decode to {KEY_BYTES} bytes, got {len(key)}")
    return key


def key_id(key: bytes) -> str:
    """A short, non-secret fingerprint stored beside each ciphertext, so a value
    sealed under a rotated-away key is diagnosable instead of merely absent."""
    return hashlib.sha256(b"bare-retention-key-id\x1f" + key).hexdigest()[:8]


# --- values ------------------------------------------------------------------


def encrypt_value(plaintext: str, *, run_id: str, value_hash: str, key: bytes) -> str:
    """Seal one retained value for storage in ``evidence.value_plaintext``."""
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _aad(run_id, value_hash))
    body = base64.urlsafe_b64encode(nonce + sealed).decode("ascii")
    return f"{CIPHERTEXT_PREFIX}{key_id(key)}:{body}"


def decrypt_value(stored: str, *, run_id: str, value_hash: str, key: bytes) -> str | None:
    """Open a sealed value, or ``None`` if it cannot be opened for this row."""
    if not stored.startswith(CIPHERTEXT_PREFIX):
        # A legacy unencrypted row. Served as-is it would make the encryption
        # optional in practice; migration 0005 expires these for purging.
        return None
    stored_key_id, _, body = stored[len(CIPHERTEXT_PREFIX) :].partition(":")
    if stored_key_id != key_id(key):
        return None
    try:
        raw = base64.b64decode(body.encode("ascii"), altchars=b"-_", validate=True)
        opened = AESGCM(key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], _aad(run_id, value_hash))
        return opened.decode("utf-8")
    except (InvalidTag, binascii.Error, ValueError, UnicodeError):
        return None


def _aad(run_id: str, value_hash: str) -> bytes:
    return f"{run_id}\x1f{value_hash}".encode()


# --- expiry ------------------------------------------------------------------


def retention_deadline(now: datetime, settings: Settings | None = None) -> datetime:
    """When a run retaining plaintext from ``now`` must stop serving it."""
    settings = settings or get_settings()
    return now + timedelta(hours=settings.plaintext_ttl_hours)


def plaintext_available(run: Run | None, now: datetime | None = None) -> bool:
    """Whether this run's retained values may be written or read right now.

    The single check every path goes through — sealing at scan time, the reveal
    endpoint, and the investigation tools — so the TTL cannot be enforced in one
    place and forgotten in another. A retaining run with no deadline is treated
    as expired, not as unlimited.
    """
    if run is None or not run.retain_plaintext or run.plaintext_purged_at is not None:
        return False
    if run.plaintext_expires_at is None:
        return False
    return (now or datetime.now(UTC)) < _aware(run.plaintext_expires_at)


def _aware(value: datetime) -> datetime:
    # SQLite hands timestamps back naive; they were written as UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# --- purge -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PurgeReport:
    runs: tuple[str, ...] = ()
    values: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"runs": list(self.runs), "values": self.values}


def purge_expired_plaintext(session: Session, now: datetime | None = None) -> PurgeReport:
    """Null the retained values of every run whose retention has ended.

    Idempotent: a purged run is stamped and not revisited. Each purge is an
    audit record carrying the count, so "were those secrets actually deleted,
    and when" has an answer that does not depend on reading logs.
    """
    now = now or datetime.now(UTC)
    due = session.scalars(
        select(Run)
        .where(
            Run.retain_plaintext.is_(True),
            Run.plaintext_purged_at.is_(None),
            or_(Run.plaintext_expires_at.is_(None), Run.plaintext_expires_at <= now),
        )
        .order_by(Run.id)
    ).all()

    purged: list[str] = []
    total = 0
    for run in due:
        result = session.execute(
            update(Evidence)
            .where(Evidence.run_id == run.id, Evidence.value_plaintext.is_not(None))
            .values(value_plaintext=None),
            execution_options={"synchronize_session": False},
        )
        count = max(int(result.rowcount or 0), 0)
        expired = run.plaintext_expires_at
        run.plaintext_purged_at = now
        session.add(
            AuditLog.record(
                AuditAction.PLAINTEXT_PURGED,
                run_id=run.id,
                values_purged=count,
                expired_at=_aware(expired).isoformat() if expired else None,
            )
        )
        purged.append(run.id)
        total += count

    session.flush()
    return PurgeReport(runs=tuple(purged), values=total)
