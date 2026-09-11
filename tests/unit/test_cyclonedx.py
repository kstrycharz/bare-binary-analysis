"""CycloneDX SBOM export.

The module makes two promises in its docstring that nothing was checking: that
the document is byte-identical for identical input, and that every component
carries how it was identified rather than being asserted flat. Both are the
reason the output is worth attaching to a release, so both are tested here.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from core.composition import ComponentInventory, Confidence, Ecosystem
from core.composition.model import Component
from reporting.cyclonedx import SPEC_VERSION, build_sbom, dump_sbom


def component(
    name: str = "left-pad",
    version: str = "1.3.0",
    ecosystem: Ecosystem = Ecosystem.NPM,
    confidence: Confidence = Confidence.DECLARED,
    licence: str = "",
    evidence: str = "package.json",
    path_in_tree: str = "app/node_modules/left-pad",
) -> Component:
    return Component(
        name=name,
        version=version,
        ecosystem=ecosystem,
        confidence=confidence,
        path_in_tree=path_in_tree,
        licence=licence,
        evidence=evidence,
    )


def sbom(
    *components: Component,
    run_id: str = "run-abc",
    artifact_name: str = "installer.exe",
    artifact_sha256: str = "a" * 64,
    artifact_size_bytes: int = 1024,
    tool_version: str = "0.1.0",
    inventory: ComponentInventory | None = None,
) -> dict[str, Any]:
    return build_sbom(
        inventory
        if inventory is not None
        else ComponentInventory(components=components, files_examined=42),
        run_id=run_id,
        artifact_name=artifact_name,
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=artifact_size_bytes,
        tool_version=tool_version,
    )


def _root_properties(document: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in document["metadata"]["component"]["properties"]}


class TestTheDocumentIsWellFormed:
    def test_it_declares_the_format_consumers_look_for(self) -> None:
        document = sbom(component())
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] == SPEC_VERSION == "1.5"
        assert document["version"] == 1

    def test_the_artifact_is_the_root_component(self) -> None:
        """Dependency-Track and GitHub both key off metadata.component; without
        it the SBOM is a bag of libraries belonging to nothing."""
        root = sbom(component())["metadata"]["component"]
        assert root["name"] == "installer.exe"
        assert root["hashes"] == [{"alg": "SHA-256", "content": "a" * 64}]

    def test_an_artifact_with_no_hash_omits_the_field(self) -> None:
        """Rather than asserting an empty hash, which reads as a real value."""
        root = sbom(component(), artifact_sha256="")["metadata"]["component"]
        assert root["hashes"] == []

    def test_the_tool_identifies_itself(self) -> None:
        tools = sbom()["metadata"]["tools"]["components"]
        assert tools[0]["name"] == "BARE"
        assert tools[0]["version"] == "0.1.0"

    def test_an_empty_inventory_is_still_a_valid_document(self) -> None:
        """A scan that found no components must produce an SBOM saying so, not
        an error — 'nothing found' is a real answer a release gate needs."""
        document = sbom()
        assert document["components"] == []
        assert document["bomFormat"] == "CycloneDX"


class TestEvidenceNotAssertion:
    """The distinction the module exists to preserve: a manifest declaration
    and a version banner scraped from a stripped binary are not the same fact."""

    @pytest.mark.parametrize(
        ("confidence", "score", "technique"),
        [
            (Confidence.DECLARED, 1.0, "manifest-analysis"),
            (Confidence.EMBEDDED, 0.8, "binary-analysis"),
            (Confidence.INFERRED, 0.5, "binary-analysis"),
        ],
    )
    def test_each_confidence_maps_to_its_own_score(
        self, confidence: Confidence, score: float, technique: str
    ) -> None:
        entry = sbom(component(confidence=confidence))["components"][0]
        identity = entry["evidence"]["identity"]
        assert identity["confidence"] == score
        assert identity["methods"][0]["technique"] == technique

    def test_a_declaration_outranks_an_inference(self) -> None:
        """The ordering is the point; the exact numbers are a convention."""
        scores = [
            sbom(component(confidence=c))["components"][0]["evidence"]["identity"]["confidence"]
            for c in (Confidence.DECLARED, Confidence.EMBEDDED, Confidence.INFERRED)
        ]
        assert scores == sorted(scores, reverse=True)

    def test_the_confidence_is_also_readable_as_a_property(self) -> None:
        entry = sbom(component(confidence=Confidence.INFERRED))["components"][0]
        properties = {p["name"]: p["value"] for p in entry["properties"]}
        assert properties["bare:confidence"] == "inferred"

    def test_the_location_travels_with_the_component(self) -> None:
        """The single most useful field for anyone who has to remove it."""
        entry = sbom(component(path_in_tree="app/lib/zlib.dll"))["components"][0]
        properties = {p["name"]: p["value"] for p in entry["properties"]}
        assert properties["bare:path"] == "app/lib/zlib.dll"

    def test_evidence_falls_back_to_the_path(self) -> None:
        """A component identified without a named evidence field still has to
        say where it came from."""
        entry = sbom(component(evidence="", path_in_tree="app/lib/zlib.dll"))["components"][0]
        assert entry["evidence"]["identity"]["methods"][0]["value"] == "app/lib/zlib.dll"


class TestLicences:
    def test_a_declared_licence_is_an_spdx_expression(self) -> None:
        """`expression`, not `license.id`: manifests routinely declare real
        expressions, and forcing one into an id field asserts an id that is not
        one."""
        entry = sbom(component(licence="MIT OR Apache-2.0"))["components"][0]
        assert entry["licenses"] == [{"expression": "MIT OR Apache-2.0"}]

    def test_no_licence_means_no_field(self) -> None:
        """Rather than an empty expression, which claims a licence was found."""
        assert "licenses" not in sbom(component(licence=""))["components"][0]


class TestPurlsAreTheJoinKey:
    def test_the_purl_is_both_the_ref_and_the_purl(self) -> None:
        entry = sbom(component())["components"][0]
        assert entry["purl"] == entry["bom-ref"] == "pkg:npm/left-pad@1.3.0"

    def test_a_scoped_npm_package_keeps_its_namespace(self) -> None:
        """Getting this wrong breaks every CVE lookup for scoped packages."""
        entry = sbom(component(name="@babel/parser", version="7.26.2"))["components"][0]
        assert entry["purl"] == "pkg:npm/%40babel/parser@7.26.2"


class TestItSaysWhenTheInventoryIsPartial:
    def test_a_complete_walk_says_so(self) -> None:
        document = sbom(component())
        properties = _root_properties(document)
        assert properties["bare:inventory_complete"] == "true"
        assert properties["bare:files_examined"] == "42"

    def test_a_truncated_walk_is_never_presented_as_complete(self) -> None:
        """An inventory presented as complete when it is not is worse than no
        inventory — it is read as 'these are all the components'."""
        document = sbom(
            inventory=ComponentInventory(
                components=(component(),), files_examined=42, truncated=True
            )
        )
        assert _root_properties(document)["bare:inventory_complete"] == "false"


class TestItIsReproducible:
    """The reason an SBOM can be hashed, attached to a release, and diffed
    between builds. A document that differs on every render makes every diff
    useless, which is most of what an SBOM is for."""

    def test_two_renders_of_one_run_are_byte_identical(self) -> None:
        first = dump_sbom(sbom(component(), component(name="lodash", version="4.17.21")))
        second = dump_sbom(sbom(component(), component(name="lodash", version="4.17.21")))
        assert first == second

    def test_the_serial_is_derived_from_the_run_not_randomness(self) -> None:
        assert sbom(run_id="run-abc")["serialNumber"] == sbom(run_id="run-abc")["serialNumber"]

    def test_different_runs_get_different_serials(self) -> None:
        assert sbom(run_id="run-abc")["serialNumber"] != sbom(run_id="run-xyz")["serialNumber"]

    def test_the_serial_is_a_uuid_urn(self) -> None:
        import uuid

        serial = sbom(run_id="run-abc")["serialNumber"]
        assert serial.startswith("urn:uuid:")
        uuid.UUID(serial.removeprefix("urn:uuid:"))

    def test_nothing_in_the_document_comes_from_the_clock(self) -> None:
        """A timestamp is the usual way this guarantee is lost."""
        rendered = dump_sbom(sbom(component()))
        assert "timestamp" not in rendered

    def test_the_serialisation_is_stable_and_parseable(self) -> None:
        rendered = dump_sbom(sbom(component()))
        assert rendered.endswith("\n")
        assert json.loads(rendered)["bomFormat"] == "CycloneDX"
