"""SARIF 2.1.0 output.

SARIF is how a finding stops being a wall of CI log text and becomes an
annotation on the pull request that introduced it. GitHub code scanning,
GitLab, Azure DevOps, and every serious IDE read it, which means the fastest
path to "developers actually see this" is emitting it correctly rather than
building a bespoke integration per platform.

Two decisions worth stating:

**Masked values only.** A SARIF file is uploaded to a code-scanning service and
often retained long past the run. Putting candidate secret plaintext in it
would re-leak the exact thing the tool exists to catch (§14). Every message
carries the masked value and the rule, never the secret.

**Levels are not severities.** SARIF has three result levels; the product has
five severities. The mapping is lossy in one direction, so the original
severity is preserved in ``properties`` and in the rule metadata, which is what
platform filtering and the security-severity score actually read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from core.policy import GateVerdict
from core.vocab import Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF's three levels against the product's five severities. Medium maps to
# `warning` rather than `error` deliberately: a gate that annotates every PDB
# path as an error is one developers learn to ignore.
_LEVEL_BY_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub reads `security-severity` as a CVSS-like number and derives its own
# critical/high/medium/low buckets from it. Without it every result lands in
# one undifferentiated pile.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


@dataclass(frozen=True, slots=True)
class SarifFinding:
    """The projection SARIF needs.

    Separate from :class:`~core.policy.GateFinding` because a report carries
    things a gate decision does not — remediation prose, CWE, byte offsets —
    and coupling them would drag report concerns into the gate.
    """

    id: str
    rule_id: str
    title: str
    severity: Severity
    value_masked: str
    artifact_path: str
    offset: int | None = None
    category: str = ""
    cwe: str | None = None
    remediation_md: str | None = None
    is_new: bool = True
    status: str = "open"
    blocked_release: bool = False


def _rule_descriptor(rule_id: str, findings: list[SarifFinding]) -> dict[str, Any]:
    worst = min((f.severity for f in findings), key=lambda s: s.rank)
    sample = findings[0]
    help_text = sample.remediation_md or (
        "Remove the value from the shipped artifact and rotate it if it is live."
    )
    descriptor: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": sample.title},
        "fullDescription": {"text": f"BARE rule {rule_id} matched in a shipped artifact."},
        "help": {"text": help_text, "markdown": help_text},
        "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[worst]},
        "properties": {
            "tags": [t for t in ("security", sample.category) if t],
            "security-severity": _SECURITY_SEVERITY[worst],
            "bare-severity": worst.value,
        },
    }
    if sample.cwe:
        # GitHub renders external/CWE tags in its security overview.
        tags = descriptor["properties"]["tags"]
        assert isinstance(tags, list)
        tags.append(f"external/cwe/{sample.cwe.lower()}")
    return descriptor


def _result(finding: SarifFinding, rule_index: int) -> dict[str, Any]:
    # A binary offset is not a line number. SARIF's region supports byte
    # offsets, and using them keeps an annotation truthful about where in the
    # artifact the match sits rather than inventing a line.
    region: dict[str, Any] = {}
    if finding.offset is not None:
        region = {"byteOffset": finding.offset, "byteLength": max(len(finding.value_masked), 1)}

    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.artifact_path or "unknown"},
        }
    }
    if region:
        location["physicalLocation"]["region"] = region

    message = f"{finding.title}: {finding.value_masked}"
    if finding.is_new:
        message += " (introduced by this build)"

    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": message},
        "locations": [location],
        # Stable across runs, so a code-scanning service tracks a finding
        # rather than re-opening it on every build (ADR-0010).
        "partialFingerprints": {"bareFindingId": finding.id},
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category,
            "status": finding.status,
            "isNew": finding.is_new,
            "blocksRelease": finding.blocked_release,
        },
    }


def build_sarif(
    findings: list[SarifFinding],
    *,
    tool_version: str,
    verdict: GateVerdict | None = None,
    artifact_name: str = "",
    run_id: str = "",
    information_uri: str = "https://github.com/bare/bare",
) -> dict[str, Any]:
    """Build a SARIF log. Deterministic: rules and results are both sorted."""
    ordered = sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.id))

    by_rule: dict[str, list[SarifFinding]] = {}
    for finding in ordered:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    rule_ids = sorted(by_rule)
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [_rule_descriptor(rule_id, by_rule[rule_id]) for rule_id in rule_ids]

    run_properties: dict[str, Any] = {"bareRunId": run_id}
    if artifact_name:
        run_properties["artifact"] = artifact_name
    if verdict is not None:
        run_properties["gate"] = {
            "decision": verdict.decision.value,
            "policy": verdict.policy_name,
            "violations": len(verdict.violations),
            "waived": len(verdict.waived),
            "inherited": len(verdict.inherited),
            "degradedStages": list(verdict.degraded_stages),
        }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "BARE",
                        "version": tool_version,
                        "informationUri": information_uri,
                        "rules": rules,
                    }
                },
                "results": [_result(f, rule_index[f.rule_id]) for f in ordered],
                "properties": run_properties,
            }
        ],
    }


def dump_sarif(log: dict[str, Any]) -> str:
    """Serialise deterministically — byte-identical for identical input."""
    return json.dumps(log, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
