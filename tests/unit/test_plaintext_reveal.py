"""Retrieving retained plaintext for a finding.

The bug this exists for shipped and was caught on a real artifact: plaintext
was matched to a finding by ``value_hash``, which works for an ordinary finding
and silently fails for a *clustered* one. A cluster's hash is derived from its
members' hashes (`correlator.py`), so by construction it equals no evidence
row's hash — and clusters are exactly the findings with the most values to
show. On a real game binary the operator saw 40 masked source paths and no way
to reveal any of them.

So the case that matters here is the cluster, and the link that has to hold is
locations, not hashes.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.routers.findings import _context_plaintext, _plaintexts
from core.models import Artifact, Evidence, Finding, FindingLocation, Run
from core.models.base import Base
from core.models.enums import ArtifactKind, RunStatus
from core.vocab import Severity

REAL = [
    r"Z:\repo\ares\Engine\Code\Eugen\CPP\NavMesh\UnitTests.cpp",
    r"Z:\repo\ares\Crux\Code\Eugen\CPP\EugSound\SoundEngine.cpp",
    r"Z:\repo\ares\WarGame\Bin\WarGame.Final.x64.pdb",
]


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        yield active


def _run(session: Session) -> Run:
    run = Run(
        id="r1",
        status=RunStatus.COMPLETED,
        profile="standard",
        attested_by="kyle",
        attestation_reference="SEC-1",
        attested_at=datetime.now(UTC),
        retain_plaintext=True,
    )
    session.add(run)
    session.add(
        Artifact(
            id="a1",
            run_id="r1",
            name="game.exe",
            path_in_tree="game.exe",
            depth=0,
            sha256="0" * 64,
            size_bytes=1024,
            kind=ArtifactKind.PE,
        )
    )
    session.flush()
    return run


def _evidence(session: Session, offset: int, plaintext: str | None) -> None:
    session.add(
        Evidence(
            run_id="r1",
            artifact_id="a1",
            analyzer="static",
            rule_id="windows-source-file-path",
            value_hash=f"{offset:064d}",
            value_masked="Z:\\r" + "\u2022" * 12 + ".cpp",
            value_plaintext=plaintext,
            offset=offset,
        )
    )


def _finding(session: Session, *, value_hash: str, offsets: list[int]) -> Finding:
    finding = Finding(
        id="f1",
        run_id="r1",
        rule_id="windows-source-file-path",
        category="disclosure",
        title="Source file path",
        severity=Severity.MEDIUM.value,
        confidence=0.8,
        value_masked="masked",
        value_hash=value_hash,
    )
    session.add(finding)
    locations = [
        FindingLocation(
            finding_id="f1",
            run_id="r1",
            artifact_id="a1",
            path_in_tree="game.exe",
            offset=offset,
        )
        for offset in offsets
    ]
    session.add_all(locations)
    session.flush()
    return finding


class TestClusteredFindings:
    def test_a_cluster_reveals_every_value_it_covers(self, session: Session) -> None:
        """The regression. `value_hash` here is a synthetic cluster hash that
        matches no evidence row, which is precisely why the hash join returned
        nothing and the reveal button never appeared."""
        _run(session)
        for index, value in enumerate(REAL):
            _evidence(session, offset=100 + index, plaintext=value)
        finding = _finding(
            session, value_hash="cluster-hash-matching-no-evidence", offsets=[100, 101, 102]
        )

        locations = list(finding.locations)
        assert sorted(_plaintexts(session, finding, locations)) == sorted(REAL)

    def test_it_does_not_leak_values_from_other_findings(self, session: Session) -> None:
        """Locations are the link, so a finding must return only what its own
        locations point at — not every retained value in the run."""
        _run(session)
        _evidence(session, offset=100, plaintext=REAL[0])
        _evidence(session, offset=999, plaintext="SHOULD-NOT-APPEAR")
        finding = _finding(session, value_hash="h", offsets=[100])

        assert _plaintexts(session, finding, list(finding.locations)) == [REAL[0]]


class TestOrdinaryFindings:
    def test_a_single_value_finding_still_reveals(self, session: Session) -> None:
        _run(session)
        _evidence(session, offset=100, plaintext=REAL[2])
        finding = _finding(session, value_hash="h", offsets=[100])

        assert _plaintexts(session, finding, list(finding.locations)) == [REAL[2]]

    def test_duplicates_collapse(self, session: Session) -> None:
        """The same path at three offsets is one value worth showing."""
        _run(session)
        for offset in (100, 101, 102):
            _evidence(session, offset=offset, plaintext=REAL[0])
        finding = _finding(session, value_hash="h", offsets=[100, 101, 102])

        assert _plaintexts(session, finding, list(finding.locations)) == [REAL[0]]


class TestRunsWithoutRetention:
    def test_nothing_is_returned_when_plaintext_was_never_stored(self, session: Session) -> None:
        """The default. Masked and hashed only."""
        _run(session)
        _evidence(session, offset=100, plaintext=None)
        finding = _finding(session, value_hash="h", offsets=[100])

        assert _plaintexts(session, finding, list(finding.locations)) == []

    def test_a_finding_with_no_locations_returns_nothing(self, session: Session) -> None:
        _run(session)
        _evidence(session, offset=100, plaintext=REAL[0])
        finding = _finding(session, value_hash="h", offsets=[])

        assert _plaintexts(session, finding, []) == []


class TestContextPlaintext:
    def _context(self, session: Session, offset: int, masked: str, raw: str | None) -> None:
        session.add(
            Evidence(
                run_id="r1",
                artifact_id="a1",
                analyzer="static",
                rule_id="windows-source-file-path",
                value_hash=f"{offset:064d}",
                value_masked="masked",
                offset=offset,
                context_snippet=masked,
                context_plaintext=raw,
            )
        )

    def test_the_unmasked_window_pairs_with_the_findings_snippet(self, session: Session) -> None:
        """A cluster has many members; the snippet on the finding is one of
        theirs, and the reveal must show that same window, not a neighbour's."""
        _run(session)
        self._context(session, 100, "a=Z:\\r••••.cpp", "a=" + REAL[0])
        self._context(session, 101, "b=Z:\\r••••.cpp", "b=" + REAL[1])
        finding = _finding(session, value_hash="h", offsets=[100, 101])
        finding.context_snippet = "b=Z:\\r••••.cpp"

        assert _context_plaintext(session, finding, list(finding.locations)) == "b=" + REAL[1]

    def test_nothing_when_the_run_did_not_retain_it(self, session: Session) -> None:
        _run(session)
        self._context(session, 100, "a=Z:\\r••••.cpp", None)
        finding = _finding(session, value_hash="h", offsets=[100])
        finding.context_snippet = "a=Z:\\r••••.cpp"

        assert _context_plaintext(session, finding, list(finding.locations)) is None
