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

A third, from ADR-0033: **while a stage runs, the same document is published
as it grows** (`LiveStageLog`), through the same renderer and to the same key,
so "show logs" during a scan reads exactly what the retained log will say.
"""

from __future__ import annotations

import time
from collections.abc import Callable
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

# What `DockerDriver._collect_logs()` appends when its 8 MiB collection cap fires.
_DRIVER_TRUNCATION_MARKER = "[bare: log truncated]\n"
_STORED_TRUNCATION_NOTE = "\n[bare: stored log truncated]\n"

_HEADLINE = "--- {stream} ---\n"

# The floor between two published snapshots of a running stage. Each snapshot
# is a rule-pack pass over everything the stage has printed so far, so the
# real interval also stretches with that cost — see `LiveStageLog`.
LIVE_LOG_INTERVAL_S = 5.0
# A snapshot is not retaken sooner than this many times the last one's cost:
# an analyzer printing megabytes spends most of its time analysing, not being
# redacted.
_LIVE_COST_MULTIPLE = 4.0
# After a bucket failure, wait this long before trying again rather than
# warning on every tick of a scan that may run for half an hour.
_LIVE_FAILURE_BACKOFF_S = 30.0


def render_stage_log(
    stdout: bytes, stderr: bytes, *, pack: RulePack, live: bool = False
) -> tuple[str, bool]:
    """The retained document, and whether either stream was cut to fit.

    Deterministic by construction: fixed section order, one pass of the rule
    pack over each stream, explicit masking of every matched value. Both
    streams are included even when empty so the document always reads as
    "what the container printed", not "what survived".

    **Redact, then cap — never the other way round.** Capping first cuts a
    secret that straddles the limit into a prefix no rule recognises, and that
    prefix is then stored in the clear: `key=AKIAIO` was observed doing exactly
    this. Scanning the whole stream is bounded by the driver's own collection
    cap — about 5 s per stream at 8 MiB, against a scan measured in minutes —
    and cutting already-masked text can only ever shorten a mask.

    ``live`` is for a container that is still running, and holds back each
    stream's unfinished last line. It is the same hazard as the cap: a process
    caught mid-``write`` has printed the first half of a key, which no rule
    recognises. Holding back one line is enough because matching never crosses
    one — the extractor splits strings at newlines, and proximity rules look
    inside the extracted string — so a finished line redacts now exactly as
    it will in the retained log. The held-back line appears whole in the next
    snapshot.
    """
    truncated = False
    parts: list[str] = []
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        text = raw.decode("utf-8", "replace")
        if text.endswith(_DRIVER_TRUNCATION_MARKER):
            # The driver's own cap fired; nothing added here will make that
            # less true, but the reader should see both truncations.
            truncated = True
            body = text[: -len(_DRIVER_TRUNCATION_MARKER)]
            text = _drop_partial_line(body) + _DRIVER_TRUNCATION_MARKER
        elif live:
            text = text[: text.rfind("\n") + 1]
        text = redact_log_text(text, pack=pack)
        encoded = text.encode("utf-8")
        if len(encoded) > MAX_STORED_LOG_BYTES:
            # "ignore", not "replace": a cut through a multi-byte mask glyph
            # drops the fragment rather than inventing a character.
            text = encoded[:MAX_STORED_LOG_BYTES].decode("utf-8", "ignore")
            text += _STORED_TRUNCATION_NOTE
            truncated = True
        parts.append(_HEADLINE.format(stream=name) + text)

    return "\n".join(parts), truncated


def _drop_partial_line(text: str) -> str:
    """Remove the line the driver's byte cap cut through.

    That cap counts bytes, not lines, so its last line can be the first
    nineteen characters of a twenty-character key — a fragment no rule can
    recognise and therefore none can mask. One lost line of a log already
    past 8 MiB is the cheaper failure.
    """
    body = text.removesuffix("\n")  # the separator the driver puts before its marker
    return body[: body.rfind("\n") + 1]


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

    A match is replaced in both the forms the scanner reads: plain, and
    UTF-16LE (each character followed by a NUL), because an analyzer dumping a
    Windows string table echoes it wide and the scanner finds it there.
    """
    if not text:
        return text
    # dict.fromkeys, not a set: set iteration order depends on PYTHONHASHSEED,
    # and a length-tie in the sort would otherwise leak into stored text
    # (determinism, §8).
    unique = dict.fromkeys(m.value for m in scan_bytes(text.encode("utf-8", "replace"), pack))
    values = sorted(unique, key=len, reverse=True)
    for value in values:
        masked = mask(value)
        text = text.replace(value, masked)
        text = text.replace("".join(f"{c}\x00" for c in value), masked)
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


class LiveStageLog:
    """Publishes a running stage's output where its retained log will go.

    Handed to the sandbox driver as its ``on_output`` callback, which offers it
    everything the container has printed so far every couple of seconds. A
    snapshot is rendered by `render_stage_log` with ``live=True`` and written
    to `stage_log_key` — the key `store_stage_log` overwrites when the stage
    ends — so a reader polling one address sees the document grow and then
    settle into the retained copy (ADR-0033). The stage row is not touched:
    nothing is committed mid-stage, and ``log_key`` stays the statement that
    a *finished* stage kept its log.

    Throttled on two clocks: never more often than ``interval_s``, and never
    more often than `_LIVE_COST_MULTIPLE` times the last snapshot's cost.
    Output that has not grown is not re-rendered, and a document identical to
    the last one is not rewritten.

    Never raises: it runs on the thread enforcing the container's deadline,
    and a broken live view must not turn a healthy analyzer into a degraded
    stage (ADR-0008).
    """

    def __init__(
        self,
        store: ObjectStore,
        *,
        run_id: str,
        stage_id: str,
        pack: RulePack,
        interval_s: float = LIVE_LOG_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._run_id = run_id
        self._stage_id = stage_id
        self._pack = pack
        self._interval_s = interval_s
        self._clock = clock
        self._next_at = float("-inf")
        self._seen_bytes: int | None = None
        self._published: str | None = None
        self._bucket_ready = False

    @property
    def key(self) -> str:
        return stage_log_key(self._run_id, self._stage_id)

    def __call__(self, stdout: bytes, stderr: bytes) -> None:
        started = self._clock()
        if started < self._next_at:
            return
        size = len(stdout) + len(stderr)
        if size == self._seen_bytes:
            return
        try:
            document, _ = render_stage_log(stdout, stderr, pack=self._pack, live=True)
            if document != self._published:
                if not self._bucket_ready:
                    self._store.ensure_bucket()
                    self._bucket_ready = True
                self._store.client.put_object(
                    Bucket=self._store.bucket, Key=self.key, Body=document.encode("utf-8")
                )
                self._published = document
        except Exception as exc:
            log.warning(
                "logs.live_store_failed",
                run_id=self._run_id,
                stage_id=self._stage_id,
                error=str(exc),
            )
            self._next_at = self._clock() + _LIVE_FAILURE_BACKOFF_S
            return
        self._seen_bytes = size
        finished = self._clock()
        self._next_at = finished + max(self._interval_s, _LIVE_COST_MULTIPLE * (finished - started))


def read_stage_log(store: ObjectStore, key: str) -> str:
    response = store.client.get_object(Bucket=store.bucket, Key=key)
    body: bytes = response["Body"].read()
    return body.decode("utf-8", "replace")
