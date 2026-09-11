"""Component identification and SBOM export.

The join key for every advisory database is the PURL, so most of what matters
here is getting that string exactly right. A purl that looks plausible and
matches nothing is worse than no purl: it produces an SBOM that reports zero
vulnerabilities and is believed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.composition import Component, Confidence, Ecosystem, detect_in_file, inventory
from reporting.cyclonedx import SPEC_VERSION, build_sbom, dump_sbom


def _component(name: str, version: str, ecosystem: Ecosystem = Ecosystem.NPM) -> Component:
    return Component(
        name=name,
        version=version,
        ecosystem=ecosystem,
        confidence=Confidence.DECLARED,
        path_in_tree="app.asar/node_modules",
    )


class TestPackageUrls:
    def test_scoped_npm_keeps_its_at_sign_encoded(self) -> None:
        """The spec's own example. Stripping the `@` yields a purl that looks
        right and matches nothing in any advisory database."""
        assert (
            _component("@angular/animation", "12.3.1").purl
            == "pkg:npm/%40angular/animation@12.3.1"
        )

    def test_unscoped_npm(self) -> None:
        assert _component("lodash", "4.17.21").purl == "pkg:npm/lodash@4.17.21"

    def test_go_module_path_becomes_a_namespace(self) -> None:
        component = _component("github.com/spf13/cobra", "v1.8.0", Ecosystem.GOLANG)
        assert component.purl == "pkg:golang/github.com/spf13/cobra@v1.8.0"

    def test_nuget(self) -> None:
        component = _component("Newtonsoft.Json", "13.0.3", Ecosystem.NUGET)
        assert component.purl == "pkg:nuget/Newtonsoft.Json@13.0.3"

    def test_unsafe_characters_are_encoded(self) -> None:
        assert "%20" in _component("weird name", "1.0").purl

    def test_ecosystem_value_is_the_purl_type(self) -> None:
        """The enum value *is* the purl type, so the two cannot drift."""
        for ecosystem in Ecosystem:
            assert _component("x", "1", ecosystem).purl.startswith(f"pkg:{ecosystem.value}/")


class TestPackageJson:
    def test_reads_name_version_and_licence(self, tmp_path: Path) -> None:
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "@babel/parser", "version": "7.26.2", "license": "MIT"}),
            encoding="utf-8",
        )
        found = detect_in_file(manifest, "app.asar/node_modules/@babel/parser/package.json")
        assert len(found) == 1
        assert found[0].name == "@babel/parser"
        assert found[0].version == "7.26.2"
        assert found[0].licence == "MIT"
        assert found[0].confidence is Confidence.DECLARED

    def test_licence_object_form(self, tmp_path: Path) -> None:
        """Older packages express the licence as an object."""
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "old", "version": "1.0.0", "license": {"type": "BSD-3-Clause"}}),
            encoding="utf-8",
        )
        assert detect_in_file(manifest, "x")[0].licence == "BSD-3-Clause"

    def test_manifest_without_a_version_is_not_a_component(self, tmp_path: Path) -> None:
        """A package.json with no version is a project scaffold or a config
        file — reporting it as a shipped component is noise."""
        manifest = tmp_path / "package.json"
        manifest.write_text(json.dumps({"name": "my-app"}), encoding="utf-8")
        assert detect_in_file(manifest, "x") == []

    def test_malformed_json_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        """Hostile input is the whole job here."""
        manifest = tmp_path / "package.json"
        manifest.write_text("{not json at all", encoding="utf-8")
        assert detect_in_file(manifest, "x") == []

    def test_oversized_manifest_is_skipped(self, tmp_path: Path) -> None:
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "big", "version": "1.0", "pad": "x" * (600 * 1024)}),
            encoding="utf-8",
        )
        assert detect_in_file(manifest, "x") == []


class TestOtherEcosystems:
    def test_nuspec(self, tmp_path: Path) -> None:
        manifest = tmp_path / "Newtonsoft.Json.nuspec"
        manifest.write_text(
            "<package><metadata><id>Newtonsoft.Json</id>"
            "<version>13.0.3</version><license type='expression'>MIT</license>"
            "</metadata></package>",
            encoding="utf-8",
        )
        found = detect_in_file(manifest, "app/lib.nuspec")
        assert found[0].ecosystem is Ecosystem.NUGET
        assert found[0].purl == "pkg:nuget/Newtonsoft.Json@13.0.3"

    def test_python_dist_info_metadata(self, tmp_path: Path) -> None:
        manifest = tmp_path / "METADATA"
        manifest.write_text(
            "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nLicense: Apache-2.0\n",
            encoding="utf-8",
        )
        found = detect_in_file(manifest, "lib/requests-2.31.0.dist-info/METADATA")
        assert found[0].purl == "pkg:pypi/requests@2.31.0"

    def test_metadata_outside_dist_info_is_ignored(self, tmp_path: Path) -> None:
        """`METADATA` is only a Python manifest inside a .dist-info; elsewhere
        it is any file with that name."""
        manifest = tmp_path / "METADATA"
        manifest.write_text("Name: not-a-package\nVersion: 1.0\n", encoding="utf-8")
        assert detect_in_file(manifest, "some/other/METADATA") == []


class TestInventory:
    def test_deduplicates_the_same_component(self, tmp_path: Path) -> None:
        """A library vendored into forty places is one component with forty
        locations, not forty components."""
        files = []
        for index in range(3):
            directory = tmp_path / f"copy{index}"
            directory.mkdir()
            manifest = directory / "package.json"
            manifest.write_text(
                json.dumps({"name": "lodash", "version": "4.17.21"}), encoding="utf-8"
            )
            files.append((manifest, f"copy{index}/package.json"))

        result = inventory(files)
        assert len(result.components) == 1
        assert result.components[0].name == "lodash"

    def test_is_deterministic(self, tmp_path: Path) -> None:
        """An SBOM that reorders between builds makes every diff useless."""
        files = []
        for name in ("zulu", "alpha", "mike"):
            directory = tmp_path / name
            directory.mkdir()
            manifest = directory / "package.json"
            manifest.write_text(
                json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
            )
            files.append((manifest, f"{name}/package.json"))

        first = inventory(files).components
        second = inventory(list(reversed(files))).components
        assert [c.purl for c in first] == [c.purl for c in second]

    def test_respects_its_cap_and_says_so(self, tmp_path: Path) -> None:
        files = []
        for index in range(5):
            directory = tmp_path / str(index)
            directory.mkdir()
            manifest = directory / "package.json"
            manifest.write_text(
                json.dumps({"name": f"pkg{index}", "version": "1.0"}), encoding="utf-8"
            )
            files.append((manifest, f"{index}/package.json"))

        result = inventory(files, max_components=2)
        assert result.truncated is True
        assert len(result.components) <= 3


class TestCycloneDx:
    @pytest.fixture
    def document(self) -> dict:
        result = inventory([])
        result = type(result)(
            components=(
                _component("@babel/parser", "7.26.2"),
                Component(
                    name="zlib",
                    version="1.3.1",
                    ecosystem=Ecosystem.GENERIC,
                    confidence=Confidence.INFERRED,
                    path_in_tree="app.exe",
                    evidence="version banner",
                ),
            ),
            files_examined=1570,
        )
        return build_sbom(
            result,
            run_id="run-1",
            artifact_name="installer.exe",
            artifact_sha256="a" * 64,
            artifact_size_bytes=213_156_944,
            tool_version="0.0.1",
        )

    def test_envelope(self, document: dict) -> None:
        assert document["bomFormat"] == "CycloneDX"
        assert document["specVersion"] == SPEC_VERSION
        assert document["serialNumber"].startswith("urn:uuid:")

    def test_components_carry_purls(self, document: dict) -> None:
        purls = {c["purl"] for c in document["components"]}
        assert "pkg:npm/%40babel/parser@7.26.2" in purls

    def test_confidence_is_recorded_per_component(self, document: dict) -> None:
        """A declaration and a scraped banner are both useful. Presenting them
        as the same kind of fact is what makes an SBOM untrustworthy."""
        by_name = {c["name"]: c for c in document["components"]}
        assert by_name["@babel/parser"]["evidence"]["identity"]["confidence"] == 1.0
        assert by_name["zlib"]["evidence"]["identity"]["confidence"] == 0.5

    def test_licence_is_an_expression(self, document: dict) -> None:
        """Manifests declare SPDX *expressions* ("MIT OR Apache-2.0"), which do
        not fit an id field."""
        babel = next(c for c in document["components"] if c["name"] == "@babel/parser")
        assert babel.get("licenses") is None or "expression" in babel["licenses"][0]

    def test_completeness_is_stated(self, document: dict) -> None:
        properties = {
            p["name"]: p["value"] for p in document["metadata"]["component"]["properties"]
        }
        assert properties["bare:inventory_complete"] == "true"
        assert properties["bare:files_examined"] == "1570"

    def test_serialisation_is_deterministic(self, document: dict) -> None:
        assert dump_sbom(document) == dump_sbom(document)
        assert json.loads(dump_sbom(document))["specVersion"] == SPEC_VERSION


class TestLicenceExpressions:
    """npm's `license` field is often a pointer to a file, not a licence.

    Passing `./LICENSE.md` through as an SPDX expression puts a string in the
    SBOM that no downstream tool can evaluate — and a licence field that cannot
    be evaluated is worse than an absent one, because it reads as an answer.
    Observed on 4 of 1 003 components in a real Electron installer.
    """

    @pytest.mark.parametrize(
        "declared",
        ["./LICENSE.md", "SEE LICENSE IN LICENSE.txt", "../COPYING.md", "LICENSE.txt"],
    )
    def test_a_file_pointer_is_not_recorded_as_a_licence(
        self, tmp_path: Path, declared: str
    ) -> None:
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "x", "version": "1.0.0", "license": declared}),
            encoding="utf-8",
        )
        assert detect_in_file(manifest, "x")[0].licence == ""

    @pytest.mark.parametrize(
        "declared",
        ["MIT", "Apache-2.0", "MIT OR Apache-2.0", "LicenseRef-NvidiaProprietary"],
    )
    def test_real_expressions_survive(self, tmp_path: Path, declared: str) -> None:
        """Including `LicenseRef-`, which is how SPDX expresses a proprietary
        licence and is exactly what a vendor's own components declare."""
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "x", "version": "1.0.0", "license": declared}),
            encoding="utf-8",
        )
        assert detect_in_file(manifest, "x")[0].licence == declared

    def test_a_component_with_no_usable_licence_is_still_a_component(
        self, tmp_path: Path
    ) -> None:
        """Dropping the licence must not drop the component — an unlicensed
        entry in the inventory is the one someone needs to go and check."""
        manifest = tmp_path / "package.json"
        manifest.write_text(
            json.dumps({"name": "x", "version": "1.0.0", "license": "./LICENSE"}),
            encoding="utf-8",
        )
        found = detect_in_file(manifest, "x")
        assert len(found) == 1 and found[0].name == "x"
