"""S4 on the host: which binaries go to Ghidra, and what comes back from it.

No Docker and no Ghidra here: the driver and the object store are fakes, and the
fake driver answers with a result in the analyzer's contract. What is under test
is the orchestration that decides three things the product depends on — only
flagged executables are sent, only ``xref_function`` is ever written, and a
Ghidra failure is visible on its stage without making a complete run look
incomplete to the dashboard or the release gate (ADR-0034).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings
from core.models import Artifact, Finding, FindingLocation, Run, RunManifest, RunStage
from core.models.base import Base
from core.models.enums import ArtifactKind, RunStatus, StageStatus
from core.pipeline import ghidra
from core.pipeline import scan as scan_module
from core.pipeline.gate import degraded_stages as gate_view
from core.pipeline.recovery import fail_stale_enrichment_stages
from core.pipeline.stages import degraded_stages
from core.sandbox import SandboxResult, SandboxSpec, SandboxStatus
from core.sandbox.spec import OUTPUT_DIR

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)

Responder = Callable[[dict[str, Any]], dict[str, Any] | None]


# --- world ------------------------------------------------------------------
@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        yield active


def _run(session: Session, status: RunStatus = RunStatus.COMPLETED) -> Run:
    run = Run(
        status=status,
        attested_by="tester",
        attestation_reference="t",
        attested_at=NOW,
    )
    session.add(run)
    session.flush()
    session.add(
        RunManifest(
            run_id=run.id,
            bare_version="0",
            artifact_sha256="0" * 64,
            rule_pack_version="1",
            rule_pack_hash="0" * 64,
            tool_versions={"7z": "17"},
            image_digests={"static": "sha256:static"},
        )
    )
    session.flush()
    return run


def _artifact(
    session: Session,
    run: Run,
    name: str,
    *,
    kind: ArtifactKind = ArtifactKind.PE,
    root: bool = False,
    storage_key: str | None = "stored",
) -> Artifact:
    artifact = Artifact(
        run_id=run.id,
        parent_id=None,
        name=name,
        path_in_tree=name if root else f"installer.zip/{name}",
        sha256="0" * 64,
        size_bytes=100,
        kind=kind,
        storage_key=f"{storage_key}/{name}" if storage_key else None,
    )
    session.add(artifact)
    session.flush()
    return artifact


def _finding(session: Session, run: Run, artifact: Artifact, *offsets: int | None) -> Finding:
    finding = Finding(
        id=f"f-{artifact.name}-{len(offsets)}-{offsets[0]}",
        run_id=run.id,
        rule_id="aws-access-key-id",
        category="secret",
        title="AWS access key",
        severity="critical",
        value_masked="AKIA****",
        value_hash="1" * 64,
    )
    session.add(finding)
    session.flush()
    for offset in offsets:
        session.add(
            FindingLocation(
                finding_id=finding.id,
                run_id=run.id,
                artifact_id=artifact.id,
                path_in_tree=artifact.path_in_tree,
                offset=offset,
            )
        )
    session.flush()
    return finding


# --- fakes ------------------------------------------------------------------
class FakeStore:
    def __init__(self) -> None:
        self.downloaded: list[tuple[str, Path]] = []

    def download_to(self, key: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"MZ")
        self.downloaded.append((key, destination))
        return destination


class FakeDriver:
    """Stands in for DockerDriver; answers with whatever the responder returns."""

    def __init__(self, responder: Responder, *, status: SandboxStatus = SandboxStatus.COMPLETED):
        self.responder = responder
        self.status = status
        self.specs: list[SandboxSpec] = []
        self.staged: list[list[str]] = []
        self.on_output: list[Any] = []

    def run(self, spec: SandboxSpec, *, on_output: Any = None) -> SandboxResult:
        self.specs.append(spec)
        self.on_output.append(on_output)
        inputs = next(Path(m.source) for m in spec.mounts if m.target != OUTPUT_DIR)
        outputs = next(Path(m.source) for m in spec.mounts if m.target == OUTPUT_DIR)
        self.staged.append(sorted(p.name for p in (inputs / "binaries").iterdir()))
        order = json.loads((inputs / "targets.json").read_text(encoding="utf-8"))
        payload = self.responder(order)
        if payload is not None:
            (outputs / "result.json").write_text(json.dumps(payload), encoding="utf-8")
        return SandboxResult(
            spec=spec,
            status=self.status,
            exit_code=0 if self.status is SandboxStatus.COMPLETED else None,
            stdout=b"",
            stderr=b"",
            started_at=NOW,
            finished_at=NOW,
            image_digest="sha256:ghidra",
            error=None if self.status is SandboxStatus.COMPLETED else "watchdog fired",
        )

    def close(self) -> None:
        pass


def resolves_everything(order: dict[str, Any]) -> dict[str, Any]:
    """A Ghidra that finds a function for every offset it is asked about."""
    return {
        "schema_version": 1,
        "analyzer": "ghidra",
        "tool_versions": {"ghidra": "12.1.3"},
        "truncated": False,
        "binaries": [
            {
                "path": binary["path"],
                "status": "analyzed",
                "targets": [
                    {
                        "file_offset": offset,
                        "found": True,
                        "references": [
                            {
                                "from_address": "0x140001457",
                                "reference_type": "DATA",
                                "function": f"fn_{offset:x}",
                            }
                        ],
                    }
                    for offset in binary["offsets"]
                ],
            }
            for binary in order["binaries"]
        ],
    }


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    settings = Settings(run_root=tmp_path / "runs", repo_root=REPO_ROOT)
    store = FakeStore()
    state: dict[str, Any] = {"settings": settings, "store": store, "driver": None}

    monkeypatch.setattr(ghidra, "get_settings", lambda: settings)
    monkeypatch.setattr(ghidra, "get_object_store", lambda: store)
    monkeypatch.setattr(ghidra, "driver_from_settings", lambda: state["driver"])
    # Live snapshots write to object storage too; a sentinel proves it is wired.
    monkeypatch.setattr(ghidra, "_live_log", lambda stage, pack: ("live", stage.id))
    # Stage logs go to object storage; that path has its own tests.
    monkeypatch.setattr(scan_module, "store_stage_log", lambda *a, **k: (None, 0, False))
    return state


def _ghidra_stage(session: Session, run: Run) -> RunStage:
    return session.scalars(
        select(RunStage).where(RunStage.run_id == run.id, RunStage.analyzer == "ghidra")
    ).one()


# --- tests ------------------------------------------------------------------
class TestWhatIsSentToGhidra:
    def test_only_executables_with_an_offset_are_selected(self, session: Session) -> None:
        run = _run(session)
        exe = _artifact(session, run, "broker.exe")
        config = _artifact(session, run, "prod.json", kind=ArtifactKind.CONFIG)
        elf = _artifact(session, run, "daemon", kind=ArtifactKind.ELF)
        _finding(session, run, exe, 0x8200)
        _finding(session, run, config, 0x10)
        _finding(session, run, elf, None)

        targets, notes = ghidra.select_targets(session, run.id)
        assert [t.path_in_tree for t in targets] == ["installer.zip/broker.exe"]
        assert targets[0].offsets == [0x8200]
        assert notes == []

    def test_offsets_from_every_finding_in_a_binary_are_merged(self, session: Session) -> None:
        run = _run(session)
        exe = _artifact(session, run, "broker.exe")
        _finding(session, run, exe, 0x30, 0x10)
        _finding(session, run, exe, 0x10)

        (target,), _ = ghidra.select_targets(session, run.id)
        assert target.offsets == [0x10, 0x30]

    def test_a_binary_whose_bytes_were_not_retained_is_noted_not_dropped_silently(
        self, session: Session
    ) -> None:
        run = _run(session)
        big = _artifact(session, run, "huge.exe", storage_key=None)
        _finding(session, run, big, 0x10)

        targets, notes = ghidra.select_targets(session, run.id)
        assert targets == []
        assert notes == ["installer.zip/huge.exe: bytes not retained, so not analysed"]

    def test_the_cap_keeps_the_binaries_with_the_most_findings(self, session: Session) -> None:
        run = _run(session)
        few = _artifact(session, run, "a.exe")
        many = _artifact(session, run, "b.exe")
        _finding(session, run, few, 0x10)
        _finding(session, run, many, 0x10, 0x20, 0x30)

        targets, notes = ghidra.select_targets(session, run.id, max_binaries=1)
        assert [t.path_in_tree for t in targets] == ["installer.zip/b.exe"]
        assert notes == ["installer.zip/a.exe: over the 1-binary cap"]


class TestWhatComesBack:
    def test_function_names_land_on_the_locations(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        exe = _artifact(session, run, "broker.exe")
        _finding(session, run, exe, 0x8200, 0x10)
        world["driver"] = FakeDriver(resolves_everything)

        outcome = ghidra.enrich_run(run.id, session)

        names = {loc.offset: loc.xref_function for loc in session.scalars(select(FindingLocation))}
        assert names == {0x8200: "fn_8200", 0x10: "fn_10"}
        assert outcome.resolved == 2
        stage = _ghidra_stage(session, run)
        assert stage.status == StageStatus.COMPLETED
        assert stage.evidence_count == 2

    def test_nothing_but_xref_function_is_touched(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        """§9: enrichment never changes what the deterministic rule produced."""
        run = _run(session)
        exe = _artifact(session, run, "broker.exe")
        finding = _finding(session, run, exe, 0x8200)
        before = (finding.severity, finding.value_hash, finding.value_masked, finding.status)
        world["driver"] = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)

        session.refresh(finding)
        assert (finding.severity, finding.value_hash, finding.value_masked, finding.status) == (
            before
        )
        assert session.scalars(select(Finding)).all() == [finding]
        (location,) = session.scalars(select(FindingLocation)).all()
        assert location.offset == 0x8200

    def test_the_manifest_records_which_ghidra_named_them(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)

        manifest = session.scalars(select(RunManifest)).one()
        assert manifest.tool_versions == {"7z": "17", "ghidra": "12.1.3"}
        assert manifest.image_digests == {"static": "sha256:static", "ghidra": "sha256:ghidra"}

    def test_binaries_are_staged_under_their_artifact_id_not_their_name(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        """Names come out of the customer's archive and can be anything."""
        run = _run(session)
        hostile = _artifact(session, run, "..")
        _finding(session, run, hostile, 0x10)
        world["driver"] = driver = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)

        assert driver.staged == [[hostile.id]]

    def test_the_customer_binaries_do_not_outlive_the_stage(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)

        assert not (world["settings"].run_root / run.id / "ghidra").exists()

    def test_the_container_gets_ghidras_own_memory_ceiling(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = driver = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)

        (spec,) = driver.specs
        assert spec.image.startswith("bare/ghidra:") or "ghidra" in spec.image
        assert spec.mem_limit_bytes == int(world["settings"].ghidra_memory_gb * 1024**3)
        assert spec.timeout_s == ghidra.GHIDRA_TIMEOUT_S
        # Visible while it runs, like every other stage (ADR-0033).
        assert driver.on_output == [("live", _ghidra_stage(session, run).id)]


class TestNothingToDo:
    def test_a_run_with_no_flagged_executable_records_a_skipped_stage(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "prod.json", kind=ArtifactKind.CONFIG), 1)
        world["driver"] = driver = FakeDriver(resolves_everything)

        outcome = ghidra.enrich_run(run.id, session)

        assert outcome.status == StageStatus.SKIPPED
        assert driver.specs == []
        stage = _ghidra_stage(session, run)
        assert stage.status == StageStatus.SKIPPED
        assert "no executable" in (stage.error or "")

    def test_a_failed_run_is_not_enriched(self, session: Session, world: dict[str, Any]) -> None:
        run = _run(session, RunStatus.FAILED)
        world["driver"] = driver = FakeDriver(resolves_everything)
        assert ghidra.enrich_run(run.id, session).status == "not_applicable"
        assert driver.specs == []

    def test_a_second_delivery_does_not_run_ghidra_again(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = driver = FakeDriver(resolves_everything)

        ghidra.enrich_run(run.id, session)
        again = ghidra.enrich_run(run.id, session)

        assert again.status == "already_handled"
        assert len(driver.specs) == 1


class TestGhidraFailingIsVisibleButNotDegrading:
    def _failing(self, *statuses: str) -> Responder:
        def respond(order: dict[str, Any]) -> dict[str, Any]:
            payload = resolves_everything(order)
            for binary, status in zip(payload["binaries"], statuses, strict=False):
                binary["status"] = status
                binary["reason"] = "Ghidra could not load it"
                binary["targets"] = []
            return payload

        return respond

    def test_one_failed_binary_is_named_on_a_completed_stage(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        broken = _artifact(session, run, "a-broken.exe")
        fine = _artifact(session, run, "b-fine.exe")
        _finding(session, run, broken, 0x10)
        _finding(session, run, fine, 0x10)
        world["driver"] = FakeDriver(self._failing("failed"))

        ghidra.enrich_run(run.id, session)

        stage = _ghidra_stage(session, run)
        assert stage.status == StageStatus.COMPLETED
        assert "failed (Ghidra could not load it)" in (stage.error or "")
        assert "a-broken.exe" in (stage.error or "") or "b-fine.exe" in (stage.error or "")

    def test_every_binary_failing_fails_the_stage(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = FakeDriver(self._failing("timeout"))

        ghidra.enrich_run(run.id, session)

        assert _ghidra_stage(session, run).status == StageStatus.FAILED

    def test_no_result_file_is_a_failure(self, session: Session, world: dict[str, Any]) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = FakeDriver(lambda order: None)

        ghidra.enrich_run(run.id, session)

        stage = _ghidra_stage(session, run)
        assert stage.status == StageStatus.FAILED
        assert stage.error == "the analyzer exited without writing a result"

    def test_a_container_timeout_is_recorded_as_a_timeout(
        self, session: Session, world: dict[str, Any]
    ) -> None:
        run = _run(session)
        _finding(session, run, _artifact(session, run, "broker.exe"), 0x10)
        world["driver"] = FakeDriver(lambda order: None, status=SandboxStatus.TIMEOUT)

        ghidra.enrich_run(run.id, session)

        assert _ghidra_stage(session, run).status == StageStatus.TIMEOUT

    @pytest.mark.parametrize(
        "status",
        [StageStatus.FAILED, StageStatus.TIMEOUT, StageStatus.OOM, StageStatus.TRUNCATED],
    )
    def test_a_failed_ghidra_stage_does_not_degrade_the_run_or_the_gate(
        self, session: Session, status: StageStatus
    ) -> None:
        """The findings are all present; Ghidra could only have named functions.
        The run status and the gate read the same definition, and both must
        leave it out."""
        run = _run(session)
        session.add(RunStage(run_id=run.id, analyzer="static", status=StageStatus.COMPLETED))
        session.add(RunStage(run_id=run.id, analyzer="ghidra", status=status))
        session.flush()

        assert degraded_stages(session, run.id) == []
        assert gate_view(session, run.id) == []

    def test_a_failed_scan_stage_still_degrades_alongside_a_failed_ghidra(
        self, session: Session
    ) -> None:
        run = _run(session)
        session.add(RunStage(run_id=run.id, analyzer="static", status=StageStatus.FAILED))
        session.add(RunStage(run_id=run.id, analyzer="ghidra", status=StageStatus.FAILED))
        session.flush()

        assert gate_view(session, run.id) == ["static (failed)"]


class TestStuckStages:
    def _stage(self, session: Session, analyzer: str, started: datetime) -> RunStage:
        run = _run(session)
        stage = RunStage(
            run_id=run.id, analyzer=analyzer, status=StageStatus.RUNNING, started_at=started
        )
        session.add(stage)
        session.flush()
        return stage

    def test_a_ghidra_stage_left_running_by_a_dead_worker_is_closed(self, session: Session) -> None:
        stage = self._stage(session, "ghidra", NOW - timedelta(hours=2))

        closed = fail_stale_enrichment_stages(session, timeout_s=3600, now=NOW)

        assert closed == [stage.id]
        assert stage.status == StageStatus.FAILED
        assert "orphaned" in (stage.error or "")

    def test_a_ghidra_stage_still_within_its_time_is_left_alone(self, session: Session) -> None:
        stage = self._stage(session, "ghidra", NOW - timedelta(minutes=10))
        assert fail_stale_enrichment_stages(session, timeout_s=3600, now=NOW) == []
        assert stage.status == StageStatus.RUNNING

    def test_scan_stages_are_the_run_sweeps_business_not_this_ones(self, session: Session) -> None:
        stage = self._stage(session, "static", NOW - timedelta(hours=2))
        assert fail_stale_enrichment_stages(session, timeout_s=3600, now=NOW) == []
        assert stage.status == StageStatus.RUNNING
