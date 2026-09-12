"""Rule-pack loading and hashing."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from core.rules.model import DEFAULT_FLAGS, Pattern, Rule, RulePack
from core.vocab import Severity

RULES_GLOB = "*.yaml"
FP_CORPUS_FILE = "false_positives.yaml"


class RuleLoadError(ValueError):
    """A malformed rule. Fatal at load: a rule pack that silently drops a
    broken rule produces a scan that silently misses a class of secret."""


def load_rule_pack(directory: Path) -> RulePack:
    """Load every rule file in ``directory``.

    The pack hash covers file *contents*, sorted by filename, so it is stable
    across machines and checkouts. It goes into the run manifest, and two runs
    sharing a manifest must produce identical findings.
    """
    if not directory.is_dir():
        raise RuleLoadError(f"rule directory {directory} does not exist")

    rule_files = sorted(p for p in directory.glob(RULES_GLOB) if p.name != FP_CORPUS_FILE)
    if not rule_files:
        raise RuleLoadError(f"no rule files found in {directory}")

    digest = hashlib.sha256()
    rules: list[Rule] = []
    seen: dict[str, Path] = {}

    for path in rule_files:
        raw = path.read_bytes()
        digest.update(path.name.encode())
        digest.update(raw)

        document = yaml.safe_load(raw.decode("utf-8")) or {}
        for entry in document.get("rules", []):
            rule = _build_rule(entry, path)
            if rule.id in seen:
                raise RuleLoadError(
                    f"duplicate rule id {rule.id!r} in {path.name} "
                    f"(already defined in {seen[rule.id].name})"
                )
            seen[rule.id] = path
            rules.append(rule)

    version = _read_version(directory)
    return RulePack(
        version=version,
        rules=tuple(rules),
        hash=digest.hexdigest(),
        false_positives=_load_false_positives(directory),
    )


def _read_version(directory: Path) -> str:
    version_file = directory / "VERSION"
    if version_file.is_file():
        return version_file.read_text(encoding="utf-8").strip()
    return "0.0.0-dev"


def _load_false_positives(directory: Path) -> frozenset[str]:
    path = directory / FP_CORPUS_FILE
    if not path.is_file():
        return frozenset()
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    values: list[str] = []
    for group in document.get("known_benign", {}).values():
        values.extend(str(v) for v in group)
    return frozenset(values)


def _build_rule(entry: dict[str, Any], path: Path) -> Rule:
    try:
        rule_id = entry["id"]
        name = entry["name"]
        category = entry["category"]
        severity = Severity(entry["severity"])
        raw_patterns = entry["patterns"]
    except KeyError as exc:
        raise RuleLoadError(f"{path.name}: rule missing required field {exc}") from None
    except ValueError as exc:
        raise RuleLoadError(f"{path.name}: {entry.get('id', '?')}: {exc}") from None

    patterns: list[Pattern] = []
    for raw in raw_patterns:
        expression = raw["regex"] if isinstance(raw, dict) else raw
        capture = raw.get("capture", 0) if isinstance(raw, dict) else 0
        try:
            compiled = re.compile(expression, DEFAULT_FLAGS)
        except re.error as exc:
            raise RuleLoadError(
                f"{path.name}: {rule_id}: invalid regex {expression!r}: {exc}"
            ) from None
        patterns.append(Pattern(regex=compiled, capture=capture, source=expression))

    rejects: list[re.Pattern[str]] = []
    for expression in entry.get("rejects_matching", ()) or ():
        try:
            rejects.append(re.compile(str(expression), DEFAULT_FLAGS))
        except re.error as exc:
            raise RuleLoadError(
                f"{path.name}: {rule_id}: invalid rejects_matching regex " f"{expression!r}: {exc}"
            ) from None

    tests = entry.get("tests", {}) or {}
    return Rule(
        id=rule_id,
        name=name,
        category=category,
        severity=severity,
        patterns=tuple(patterns),
        confidence=float(entry.get("confidence", 0.5)),
        cwe=entry.get("cwe"),
        description=entry.get("description", "").strip(),
        remediation=entry.get("remediation", "").strip(),
        tags=tuple(entry.get("tags", ())),
        min_entropy=float(entry.get("min_entropy", 0.0)),
        min_length=int(entry.get("min_length", 0)),
        max_length=int(entry.get("max_length", 4096)),
        encodings=tuple(entry.get("encodings", ("ascii", "utf-16le"))),
        requires_nearby=tuple(entry.get("requires_nearby", ())),
        nearby_window=int(entry.get("nearby_window", 120)),
        shape_policy=str(entry.get("shape_policy", "context")),
        rejects_matching=tuple(rejects),
        require_mixed_case=bool(entry.get("require_mixed_case", False)),
        enabled=bool(entry.get("enabled", True)),
        examples_positive=tuple(tests.get("positive", ())),
        examples_negative=tuple(tests.get("negative", ())),
    )
