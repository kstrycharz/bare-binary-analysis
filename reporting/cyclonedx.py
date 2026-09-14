"""CycloneDX 1.5 SBOM export.

The format everything downstream consumes — Dependency-Track, GitHub, most
procurement processes — so it is the first reporting output that matters for
composition analysis.

Two decisions worth stating:

**Evidence, not assertion.** Every component carries how it was identified.
CycloneDX 1.5 has `evidence.identity` with a `confidence` field for exactly
this, and using it is the difference between an SBOM a security team trusts and
one they stop reading. A manifest declaration and a version banner scraped out
of a stripped binary are both useful; presenting them as the same kind of fact
is not.

**Deterministic.** No timestamp from the clock, no random serial — the serial
is derived from the run id. Two exports of the same run are byte-identical, so
an SBOM can be hashed, attached to a release, and compared between builds. A
document that differs on every render makes every diff useless, which is most
of what an SBOM is for.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from core.composition import ComponentInventory, Confidence

SPEC_VERSION = "1.5"

# CycloneDX expresses confidence as a number in [0, 1]. These are the honest
# readings of what each identification method is worth, not flattering ones.
_CONFIDENCE_SCORE = {
    Confidence.DECLARED: 1.0,
    Confidence.EMBEDDED: 0.8,
    Confidence.INFERRED: 0.5,
}

_CONFIDENCE_METHOD = {
    Confidence.DECLARED: "manifest-analysis",
    Confidence.EMBEDDED: "binary-analysis",
    Confidence.INFERRED: "binary-analysis",
}


def _serial(run_id: str) -> str:
    """A stable URN for this run.

    CycloneDX wants a UUID; deriving it from the run id keeps the document
    reproducible while staying unique per run.
    """
    digest = hashlib.sha256(f"bare:{run_id}".encode()).hexdigest()
    return (
        f"urn:uuid:{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-" f"{digest[16:20]}-{digest[20:32]}"
    )


def build_sbom(
    inventory: ComponentInventory,
    *,
    run_id: str,
    artifact_name: str,
    artifact_sha256: str,
    artifact_size_bytes: int,
    tool_version: str,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 document for one scanned artifact."""
    components: list[dict[str, Any]] = []
    for component in inventory.components:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": component.purl,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "evidence": {
                "identity": {
                    "field": "purl",
                    "confidence": _CONFIDENCE_SCORE[component.confidence],
                    "methods": [
                        {
                            "technique": _CONFIDENCE_METHOD[component.confidence],
                            "confidence": _CONFIDENCE_SCORE[component.confidence],
                            "value": component.evidence or component.path_in_tree,
                        }
                    ],
                }
            },
            # Where in the unpack tree this was found. Not part of the spec's
            # required shape, and the single most useful thing for anyone who
            # has to go and remove the component.
            "properties": [
                {"name": "bare:path", "value": component.path_in_tree},
                {"name": "bare:confidence", "value": component.confidence.value},
            ],
        }
        if component.licence:
            # `expression` rather than `licenses[].license.id`: what a manifest
            # declares is frequently an SPDX *expression* ("MIT OR Apache-2.0"),
            # and forcing it into an id field would either lose half of it or
            # assert an id that is not one.
            entry["licenses"] = [{"expression": component.licence}]
        components.append(entry)

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial(run_id),
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "BARE",
                        "version": tool_version,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"artifact:{artifact_sha256[:32] or run_id}",
                "name": artifact_name,
                "hashes": (
                    [{"alg": "SHA-256", "content": artifact_sha256}] if artifact_sha256 else []
                ),
                "properties": [
                    {"name": "bare:run", "value": run_id},
                    {"name": "bare:size_bytes", "value": str(artifact_size_bytes)},
                    {
                        "name": "bare:files_examined",
                        "value": str(inventory.files_examined),
                    },
                    # Stated in the document rather than only in the UI: an SBOM
                    # built from a partial walk must say so, or it will be read
                    # as a complete inventory.
                    {
                        "name": "bare:inventory_complete",
                        "value": "false" if inventory.truncated else "true",
                    },
                ],
            },
        },
        "components": components,
    }
    return document


def dump_sbom(document: dict[str, Any]) -> str:
    """Serialise deterministically — byte-identical for identical input."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
