"""The S4 result contract, as both sides of the container boundary read it.

The analyzer writes it inside the Ghidra image and the orchestrator reads it on
the host. The failure these tests are for is the quiet one: a renamed or missing
key that turns "Ghidra choked on this binary" into "Ghidra found no references",
which reads exactly like a clean result.
"""

from __future__ import annotations

import json

from core.analyzers.ghidra_result import (
    BinaryResult,
    GhidraResult,
    XrefSite,
    XrefTarget,
)


def _result() -> GhidraResult:
    return GhidraResult(
        ghidra_version="12.1.3",
        binaries=[
            BinaryResult(
                path="b/broker.exe",
                language="x86:LE:64:default",
                function_count=177,
                duration_s=11.23456,
                targets=[
                    XrefTarget(
                        file_offset=0x8200,
                        address="0x14000a000",
                        found=True,
                        references=[
                            XrefSite(from_address="0x1400001e4", reference_type="DATA"),
                            XrefSite(
                                from_address="0x140001457",
                                reference_type="DATA",
                                function="connect_broker",
                                function_address="0x140001450",
                            ),
                        ],
                    )
                ],
            ),
            BinaryResult(path="a/updater.exe", status="timeout", reason="no result within 600s"),
        ],
    )


class TestRoundTrip:
    def test_what_is_written_is_what_is_read(self) -> None:
        written = _result().to_json()
        read = GhidraResult.from_json(json.loads(json.dumps(written)))
        assert read.to_json() == written

    def test_binaries_are_written_in_path_order(self) -> None:
        """Two runs over the same tree must be byte-identical (§8)."""
        paths = [b["path"] for b in _result().to_json()["binaries"]]
        assert paths == sorted(paths)

    def test_the_version_is_recorded_where_the_manifest_merges_tool_versions(self) -> None:
        assert _result().to_json()["tool_versions"] == {"ghidra": "12.1.3"}


class TestAbsenceIsNotSuccess:
    def test_a_binary_with_no_status_reads_as_failed(self) -> None:
        """Defaulting a missing status to `analyzed` would turn a truncated
        result file into a clean bill of health."""
        assert BinaryResult.from_json({"path": "x"}).status == "failed"
        assert BinaryResult.from_json({"path": "x"}).degraded

    def test_skipped_and_analyzed_are_not_degraded(self) -> None:
        assert not BinaryResult(path="x", status="analyzed").degraded
        assert not BinaryResult(path="x", status="skipped").degraded

    def test_degraded_binaries_are_listed(self) -> None:
        assert [b.path for b in _result().degraded_binaries] == ["a/updater.exe"]

    def test_garbage_collections_do_not_crash_the_reader(self) -> None:
        read = GhidraResult.from_json({"binaries": "nope", "tool_versions": None})
        assert read.binaries == []
        assert read.ghidra_version == "unknown"


class TestXrefFunctions:
    def test_the_first_named_function_is_the_one_reported(self) -> None:
        assert _result().xref_functions() == {("b/broker.exe", 0x8200): "connect_broker"}

    def test_an_offset_with_no_function_is_absent_not_none(self) -> None:
        result = GhidraResult(
            binaries=[
                BinaryResult(
                    path="x",
                    targets=[
                        XrefTarget(
                            file_offset=1,
                            references=[XrefSite(from_address="0x1", reference_type="DATA")],
                        )
                    ],
                )
            ]
        )
        assert result.xref_functions() == {}

    def test_an_empty_function_name_is_treated_as_absent(self) -> None:
        """The Java side can write "" where a fixture writes null; neither may
        become the literal text "None" or an empty label in a report."""
        site = XrefSite.from_json({"from_address": "0x1", "function": ""})
        assert site.function is None
