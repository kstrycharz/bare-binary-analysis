"""Adding a waiver to ``.bare/waivers.yaml`` without hand-editing YAML.

The loader already refuses a waiver with no owner, no reason, or no expiry — at
release time, which is the worst moment to find out the file is wrong. This
applies the same rules when the waiver is *written*, so what lands in review is
an entry the gate will accept.

It appends text rather than round-tripping the document through a YAML emitter.
The waiver file is reviewed like code and its comments are part of the record
("confirmed inert with the vendor, SEC-4471"); ``yaml.safe_dump`` would drop
every one of them. The append is then checked by parsing the result: unless the
new document loads as exactly the old waivers plus the new one, nothing is
returned to be written.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta
from typing import Any

import yaml

from core.policy.loader import PolicyLoadError, parse_waivers
from core.policy.model import Waiver
from core.policy.policy import Policy

# Finding.compute_id: the first 32 hex characters of a SHA-256.
FINDING_ID_LENGTH = 32
_FINDING_ID_RE = re.compile(rf"^[0-9a-f]{{{FINDING_ID_LENGTH}}}$")
_PREFIX_RE = re.compile(rf"^[0-9a-f]{{1,{FINDING_ID_LENGTH - 1}}}$")
_RELATIVE_RE = re.compile(r"^(\d+)d$")
_EMPTY_FLOW_LIST_RE = re.compile(r"^waivers:[ \t]*\[[ \t]*\][ \t]*$", re.MULTILINE)
_ITEM_INDENT_RE = re.compile(r"^( *)-[ \t]+finding_id:", re.MULTILINE)

NEW_FILE_HEADER = """\
# BARE release-gate waivers.
#
# Each entry exempts one finding from the gate until it expires. Every field is
# required, and an expired waiver fails the build rather than lapsing quietly.
# Add entries with:  bare waive <finding-id> --reason ... --expires ...

waivers:
"""


class WaiveError(ValueError):
    """A waiver the gate would refuse, or a file it cannot safely be added to."""


def parse_expiry(text: str, today: date) -> date:
    """``YYYY-MM-DD``, or a relative ``30d``.

    Relative is the form people reach for under time pressure, and it is also
    the one that cannot be mistyped into the wrong year.
    """
    value = text.strip().lower()
    match = _RELATIVE_RE.match(value)
    if match:
        return today + timedelta(days=int(match.group(1)))
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise WaiveError(
            f"--expires must be a date (YYYY-MM-DD) or a number of days such as 30d, got {text!r}"
        ) from None


def build_waiver(
    *,
    finding_id: str,
    reason: str,
    owner: str,
    expires: date,
    policy: Policy,
    today: date,
) -> Waiver:
    """Validate one waiver against the policy that will judge it."""
    normalised = finding_id.strip().lower()
    if not _FINDING_ID_RE.match(normalised):
        if _PREFIX_RE.match(normalised):
            # The case this command exists for. Older gate output printed a
            # 12-character prefix, and a waiver keyed on one matches nothing:
            # the engine looks ids up exactly, so the build stays red with a
            # waiver sitting right there in the file.
            raise WaiveError(
                f"{finding_id!r} is a shortened finding id. The gate matches waivers against "
                f"the full {FINDING_ID_LENGTH}-character id, so a prefix would never apply. "
                "The full id is printed in the gate output and in `--json`."
            )
        raise WaiveError(
            f"{finding_id!r} is not a finding id (expected {FINDING_ID_LENGTH} hex characters)"
        )

    reason = reason.strip()
    owner = owner.strip()
    if policy.require_waiver_reason and not reason:
        raise WaiveError(f"a --reason is required by policy {policy.name!r}")
    if policy.require_waiver_owner and not owner:
        raise WaiveError(f"an --owner is required by policy {policy.name!r}")

    if expires < today:
        raise WaiveError(f"expiry {expires.isoformat()} is already in the past")
    days = (expires - today).days
    if days > policy.max_waiver_days:
        # Refused here rather than written and reported later: the engine
        # would decline to honour it, and the build would fail on a waiver
        # somebody believed they had granted.
        raise WaiveError(
            f"expiry {expires.isoformat()} is {days} days away; policy {policy.name!r} "
            f"allows at most {policy.max_waiver_days}"
        )

    return Waiver(finding_id=normalised, reason=reason, owner=owner, expires=expires)


def render_entry(waiver: Waiver, *, indent: str = "  ") -> str:
    """One list item. Strings go out JSON-quoted, which YAML reads as a
    double-quoted scalar — so a reason containing ``: `` or ``#`` or a newline
    cannot change the document's structure."""
    inner = indent + "  "
    return (
        f"{indent}- finding_id: {waiver.finding_id}\n"
        f"{inner}reason: {_scalar(waiver.reason)}\n"
        f"{inner}owner: {_scalar(waiver.owner)}\n"
        f"{inner}expires: {waiver.expires.isoformat()}\n"
    )


def append_waiver(existing_text: str, waiver: Waiver, policy: Policy, *, source: str) -> str:
    """Return ``existing_text`` with ``waiver`` appended.

    Raises :class:`WaiveError` if the existing file does not load, already
    waives this finding, or has a layout a plain append would corrupt.
    """
    existing = _load(existing_text, policy, source)
    for current in existing:
        if current.finding_id == waiver.finding_id:
            raise WaiveError(
                f"{source} already waives {waiver.finding_id} "
                f"(expires {current.expires.isoformat()}, owner {current.owner or 'unknown'}). "
                "Edit that entry rather than adding a second one; the gate rejects duplicates."
            )

    if not existing_text.strip():
        return NEW_FILE_HEADER + render_entry(waiver)

    text = existing_text if existing_text.endswith("\n") else existing_text + "\n"
    # `waivers: []` is what most people write to start an empty file, and an
    # item appended after a flow list is a syntax error.
    text = _EMPTY_FLOW_LIST_RE.sub("waivers:", text, count=1)
    if not _has_waivers_key(text):
        text += "\nwaivers:\n"

    indent_match = _ITEM_INDENT_RE.search(text)
    indent = indent_match.group(1) if indent_match else "  "
    entry = render_entry(waiver, indent=indent)
    candidate = text + entry

    expected = sorted([*existing, waiver], key=lambda w: (w.expires, w.finding_id))
    try:
        after = _load(candidate, policy, source)
    except WaiveError:
        after = []
    if after != expected:
        raise WaiveError(
            f"could not add to {source} safely: its layout does not allow a plain append "
            "(for example, another key follows the waiver list). Add this entry by hand:\n\n"
            + render_entry(waiver)
        )
    return candidate


def _load(text: str, policy: Policy, source: str) -> list[Waiver]:
    if not text.strip():
        return []
    try:
        raw: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise WaiveError(f"{source} is not valid YAML; fix it before adding to it: {exc}") from None
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise WaiveError(f"{source} must be a mapping with a 'waivers' list")
    try:
        return parse_waivers(raw, policy, source=source)
    except PolicyLoadError as exc:
        raise WaiveError(
            f"the existing file does not load; fix it before adding to it: {exc}"
        ) from None


def _has_waivers_key(text: str) -> bool:
    raw = yaml.safe_load(text)
    return isinstance(raw, dict) and "waivers" in raw


def _scalar(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
