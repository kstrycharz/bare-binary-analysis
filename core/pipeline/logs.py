"""Keeping the logs the scanning containers produce (bounty: `analyzer-logs`).

Today the driver collects stdout/stderr and they stop at the `SandboxResult` —
the container is gone by the time anyone asks why a stage degraded, and
`docker logs` cannot reach a container the driver has already removed (§
ADR-0003: the driver removes it deliberately, so log collection never races the
reap).

Two decisions this module embodies, argued in ADR-0032:

**Object storage, not the database row.** A 213 MB installer can produce a very
chatty analyzer. The `run_stages` row carries a key, a size, and a truncation
flag — all fixed-width — and the bytes land in the same MinIO bucket as the
artifacts, under a `logs/` prefix. "A chatty analyzer cannot grow a row without
bound" is satisfied by construction rather than by vigilance.

**The retention cap is at write time, and the redaction is not optional.**
The stored log is truncated to `MAX_STORED_LOG_BYTES` per stream, and every
candidate secret the run's own rule pack recognises in the log text is masked
with the same `mask()` the findings use. That holds whether or not the run
opted into plaintext retention: the retention opt-in is a statement about
*finding values the pipeline validated*, not about unbounded, unvalidated,
untrusted analyzer stdout that happens to echo a customer's binary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from core.rules.scanner import mask, scan_bytes
from core.storage import ObjectStore

if TYPE_CHECKING:
    from core.rules.model import RulePack

log = structlog.get_logger(__name__)

# Per stream (stdout, stderr). The driver already caps collection at 8 MiB;
# this is the *retention* cap — small enough that thousands of stage logs
# cannot dominate the bucket, large enough that a degraded run's actual error
# output fits with room to spare. A truncated log says so in text rather than
# silently cutting.
MAX_STORED_LOG_BYTES = 256 * 1024

_STDOUT_MARKER = "[bare: log truncated]"
_STORED_TRUNCATION_NOTE = "\n[bare: stored log truncated]\n"

_HEADLINE = "--- {stream} ---\n"


def render_stage_log(stdout: bytes, stderr: bytes, *, pack: RulePack) -> tuple[str, bool]:
    """The retained document, and whether either stream was cut to fit.

    Deterministic by construction: fixed section order, one pass of the rule
    pack over the joined text, explicit masking of every matched value. Both
    streams are included even when empty so the document always reads as
    "what the container printed", not "what survived".
    """
    truncated = False
    parts: list[str] = []
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        text = raw.decode("utf-8", "replace")
        if _STDOUT_MARKER in text:
            # The driver's own cap fired; nothing added here will make that
            # less true, but the reader should see both truncations.
            truncated = True
        encoded = text.encode("utf-8", "replace")
        if len(encoded) > MAX_STORED_LOG_BYTES:
            text = encoded[:MAX_STORED_LOG_BYTES].decode("utf-8", "replace")
            text += _STORED_TRUNCATION_NOTE
            truncated = True
        parts.append(_HEADLINE.format(stream=name) + text)

    return redact_log_text("\n".join(parts), pack=pack), truncated


def redact_log_text(text: str, *, pack: RulePack) -> str:
    """Mask every candidate secret the rule pack can find in ``text``.

    The log is untrusted output derived from a customer's binary — the
    analyzer prints pieces of what it read, and a tool tracing its own
    comparisons has been observed echoing whole credential strings. The same
    deterministic detectors that scan the artifact run over the log, so the
    masking cannot drift from what the run's report claims.

    Values are masked longest-first so a short value that happens to be a
    substring of a longer one cannot re-expose a character of the longer
    secret's masked form.
    """
    if not text:
        return text
    # dict.fromkeys, not a set: set iteration order depends on PYTHONHASHSEED,
    # and a length-tie in the sort would otherwise leak into stored text
    # (determinism, §8).
    unique = dict.fromkeys(m.value for m in scan_bytes(text.encode("utf-8", "replace"), pack))
    values = sorted(unique, key=len, reverse=True)
    for value in values:
        text = text.replace(value, mask(value))
    return text


def stage_log_key(run_id: str, stage_id: str) -> str:
    """Bucket key. A distinct prefix from `artifacts/` so nothing here can
    collide with the content-addressed objects or be mistaken for one."""
    return f"logs/{run_id}/{stage_id}.txt"


def store_stage_log(
    store: ObjectStore, *, run_id: str, stage_id: str, stdout: bytes, stderr: bytes, pack: RulePack
) -> tuple[str | None, int, bool]:
    """Persist one stage's log. Returns (key, bytes, truncated).

    Failures are swallowed into a warning rather than raised: a scan whose
    analyzer succeeded must not go red because the bucket hiccupped on the
    after-dinner mint of its logs (ADR-0008 — degradation degrades, it does not
    explode). The warning is logged with the stage identity so a missing log
    has a breadcrumb.
    """
    document, truncated = render_stage_log(stdout, stderr, pack=pack)
    data = document.encode("utf-8")
    key = stage_log_key(run_id, stage_id)
    try:
        store.ensure_bucket()
        store.client.put_object(Bucket=store.bucket, Key=key, Body=data)
    except Exception as exc:
        log.warning("logs.store_failed", run_id=run_id, stage_id=stage_id, error=str(exc))
        return None, 0, False
    return key, len(data), truncated


def read_stage_log(store: ObjectStore, key: str) -> str:
    response = store.client.get_object(Bucket=store.bucket, Key=key)
    body: bytes = response["Body"].read()
    return body.decode("utf-8", "replace")
