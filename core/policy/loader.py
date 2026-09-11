"""Loading policies and waivers from YAML.

Both files live in the *release* repository (``.bare/policy.yaml`` and
``.bare/waivers.yaml``), so they are reviewed like code and their history
answers "who weakened the gate, when, and why" without a separate audit trail.

Every load error is fatal. A gate that falls back to a permissive default when
its policy file has a typo is worse than no gate: the build goes green and
everybody believes it was checked.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from core.policy.model import BaselineMode, DegradedPosture, Waiver
from core.policy.policy import UNLIMITED, Budgets, Policy
from core.vocab import Severity

POLICY_DIR = ".bare"
POLICY_FILE = "policy.yaml"
WAIVERS_FILE = "waivers.yaml"

_SEVERITIES = {s.value for s in Severity}


class PolicyLoadError(ValueError):
    """A malformed policy or waiver file."""


def _require_mapping(raw: object, what: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"{what} must be a mapping, got {type(raw).__name__}")
    return raw


def _severity(value: object, field_name: str) -> Severity:
    text = str(value).strip().lower()
    if text not in _SEVERITIES:
        raise PolicyLoadError(
            f"{field_name}: unknown severity {value!r}; expected one of {sorted(_SEVERITIES)}"
        )
    return Severity(text)


def _str_set(raw: object, field_name: str) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        raise PolicyLoadError(f"{field_name} must be a list")
    return frozenset(str(item).strip() for item in raw if str(item).strip())


def _budgets(raw: object) -> Budgets:
    data = _require_mapping(raw, "budgets")
    values: dict[str, int] = {}
    for key, value in data.items():
        name = str(key).strip().lower()
        if name not in _SEVERITIES:
            raise PolicyLoadError(f"budgets: unknown severity {key!r}")
        try:
            limit = int(value)
        except (TypeError, ValueError):
            raise PolicyLoadError(f"budgets.{name} must be an integer") from None
        if limit < UNLIMITED:
            raise PolicyLoadError(f"budgets.{name} must be >= {UNLIMITED}")
        values[name] = limit
    return Budgets(**values)


def parse_policy(data: dict[str, Any], *, source: str = "<memory>") -> Policy:
    """Build a :class:`Policy` from an already-parsed mapping."""
    version = int(data.get("version", 1))
    if version != 1:
        raise PolicyLoadError(f"{source}: unsupported policy version {version}; this build reads 1")

    block = _require_mapping(data.get("block"), "block")

    floor: Severity | None
    raw_floor = block.get("severity_at_or_above", "high")
    if raw_floor is None or str(raw_floor).strip().lower() in ("none", "off", ""):
        floor = None
    else:
        floor = _severity(raw_floor, "block.severity_at_or_above")

    baseline = _require_mapping(data.get("baseline"), "baseline")
    raw_mode = str(baseline.get("mode", BaselineMode.NEW_ONLY.value)).strip().lower()
    try:
        mode = BaselineMode(raw_mode)
    except ValueError:
        raise PolicyLoadError(
            f"baseline.mode must be one of {[m.value for m in BaselineMode]}, got {raw_mode!r}"
        ) from None

    raw_degraded = str(data.get("on_degraded", DegradedPosture.FAIL.value)).strip().lower()
    try:
        degraded = DegradedPosture(raw_degraded)
    except ValueError:
        raise PolicyLoadError(
            f"on_degraded must be one of {[d.value for d in DegradedPosture]}, got {raw_degraded!r}"
        ) from None

    waivers_cfg = _require_mapping(data.get("waivers"), "waivers")
    try:
        max_days = int(waivers_cfg.get("max_ttl_days", 90))
    except (TypeError, ValueError):
        raise PolicyLoadError("waivers.max_ttl_days must be an integer") from None
    if max_days <= 0:
        raise PolicyLoadError("waivers.max_ttl_days must be positive")

    return Policy(
        name=str(data.get("name", "default")).strip() or "default",
        version=version,
        block_at_or_above=floor,
        block_categories=_str_set(block.get("categories"), "block.categories"),
        block_rules=_str_set(block.get("rules"), "block.rules"),
        budgets=_budgets(data.get("budgets")),
        baseline_mode=mode,
        on_degraded=degraded,
        trust_llm_dismissals=bool(data.get("trust_llm_dismissals", False)),
        max_waiver_days=max_days,
        require_waiver_owner=bool(waivers_cfg.get("require_owner", True)),
        require_waiver_reason=bool(waivers_cfg.get("require_reason", True)),
    )


def load_policy(path: Path) -> Policy:
    """Read a policy file. Raises :class:`PolicyLoadError` on any problem."""
    if not path.is_file():
        raise PolicyLoadError(f"policy file {path} does not exist")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"{path}: {exc}") from None
    return parse_policy(_require_mapping(raw, str(path)), source=str(path))


def _parse_date(value: object, field_name: str) -> date:
    # PyYAML already materialises unquoted ISO dates as date/datetime, so both
    # `expires: 2026-11-01` and `expires: "2026-11-01"` have to be handled.
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError:
        raise PolicyLoadError(
            f"{field_name}: expected an ISO date (YYYY-MM-DD), got {value!r}"
        ) from None


def parse_waivers(
    data: dict[str, Any], policy: Policy, *, source: str = "<memory>"
) -> list[Waiver]:
    """Build waivers, enforcing the policy's own rules about them.

    The policy governs its exemptions: if it requires an owner and a reason, a
    waiver without them is a load error, not a warning. Silently accepting a
    half-filled waiver defeats the point of writing them down.
    """
    entries = data.get("waivers", [])
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise PolicyLoadError(f"{source}: 'waivers' must be a list")

    waivers: list[Waiver] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"{source}: waivers[{index}]"
        item = _require_mapping(entry, where)

        finding_id = str(item.get("finding_id", "")).strip()
        if not finding_id:
            raise PolicyLoadError(f"{where}: finding_id is required")
        if finding_id in seen:
            raise PolicyLoadError(f"{where}: duplicate waiver for finding {finding_id}")
        seen.add(finding_id)

        reason = str(item.get("reason", "")).strip()
        if policy.require_waiver_reason and not reason:
            raise PolicyLoadError(f"{where}: a reason is required by policy {policy.name!r}")

        owner = str(item.get("owner", "")).strip()
        if policy.require_waiver_owner and not owner:
            raise PolicyLoadError(f"{where}: an owner is required by policy {policy.name!r}")

        if item.get("expires") in (None, ""):
            # Deliberately not defaulted. A waiver with no end date is a
            # permanent hole that outlives the reason it was granted for.
            raise PolicyLoadError(f"{where}: an 'expires' date is required")
        expires = _parse_date(item["expires"], f"{where}.expires")

        waivers.append(Waiver(finding_id=finding_id, reason=reason, owner=owner, expires=expires))

    waivers.sort(key=lambda w: (w.expires, w.finding_id))
    return waivers


def load_waivers(path: Path, policy: Policy) -> list[Waiver]:
    """Read a waiver file.

    A missing file is not an error — most repositories have no waivers, and
    requiring an empty file to exist is noise.
    """
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"{path}: {exc}") from None
    return parse_waivers(_require_mapping(raw, str(path)), policy, source=str(path))


def discover_policy(start: Path) -> Path | None:
    """Find ``.bare/policy.yaml`` at or above ``start``.

    Walking upward means a monorepo can hold one policy at the root and a
    stricter one beside a particular artifact, and the nearest one wins.
    """
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        path = candidate / POLICY_DIR / POLICY_FILE
        if path.is_file():
            return path
    return None
