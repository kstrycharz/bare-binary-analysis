"""Schema migrations.

The failure this exists for was live and expensive: a column was added to a
model, the deployment was rebuilt, and `create_all()` reported success because
the *table* already existed. Every request that touched the run manifest then
returned 500, and a 213 MB scan died at the manifest write with the artifact
already uploaded and unpacked.

`create_all()` is blind to a missing column by design. So the tests that matter
here are not "does the migration run" but "does a database in each of the three
states a real deployment can be in end up correct".

Migrations are exercised against SQLite: it is what the rest of the unit suite
uses, needs no Docker, and every operation these revisions perform is portable.
The Postgres-specific risk — a type that renders differently — is what
`compare_type` in `alembic/env.py` is there to catch at authoring time.
"""

from __future__ import annotations

import contextlib
import io
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, inspect, text

import core.db as db_module
from core.db import BASELINE_REVISION, _alembic_config, upgrade_schema
from core.models.base import Base


@pytest.fixture
def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Engine]:
    """A real on-disk SQLite database wired in as *the* engine.

    On-disk rather than in-memory because Alembic opens its own connection, and
    an in-memory database is not shared across connections — the migration
    would run against a second, empty database and the assertions would pass
    for the wrong reason.
    """
    url = f"sqlite:///{tmp_path / 'bare.db'}"
    active = create_engine(url, future=True)
    monkeypatch.setattr(db_module, "get_engine", lambda: active)
    yield active
    active.dispose()


def _columns(engine: Engine, table: str) -> set[str]:
    with engine.connect() as connection:
        return {c["name"] for c in inspect(connection).get_columns(table)}


def _tables(engine: Engine) -> set[str]:
    with engine.connect() as connection:
        return set(inspect(connection).get_table_names())


def _run(engine: Engine, action: object, target: str) -> None:
    """Drive Alembic against the test engine.

    The same handoff `upgrade_schema` performs: without it, `env.py` falls back
    to building an engine from settings and the migration runs against whatever
    Postgres the environment points at — which, in a unit test, is nothing.
    """
    config = _alembic_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        action(config, target)  # type: ignore[operator]


def _stamped(engine: Engine) -> str | None:
    with engine.connect() as connection:
        if "alembic_version" not in _tables(engine):
            return None
        row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
    return row[0] if row else None


class TestRevisionGraph:
    def test_there_is_exactly_one_head(self) -> None:
        """Two heads means someone branched, and `upgrade head` then fails on
        a deployment rather than in review."""
        script = ScriptDirectory.from_config(_alembic_config())
        assert len(script.get_heads()) == 1

    def test_the_baseline_this_code_stamps_actually_exists(self) -> None:
        """`upgrade_schema` names a revision as a string. If that revision is
        renamed, adoption of an existing database fails at start-up — on the
        deployment, not here, unless this test holds the two together."""
        script = ScriptDirectory.from_config(_alembic_config())
        assert script.get_revision(BASELINE_REVISION) is not None

    def test_every_revision_is_reversible(self) -> None:
        """A migration with no downgrade is a one-way door on a release that
        has to be rolled back at 3am."""
        script = ScriptDirectory.from_config(_alembic_config())
        for revision in script.walk_revisions():
            source = Path(revision.path).read_text(encoding="utf-8")
            body = source.split("def downgrade()", 1)[1]
            assert "pass" not in body.split("\n")[1], revision.revision


class TestEmptyDatabase:
    def test_migrating_from_nothing_produces_the_whole_schema(self, engine: Engine) -> None:
        upgrade_schema()
        expected = set(Base.metadata.tables)
        assert expected <= _tables(engine)

    def test_and_lands_at_head(self, engine: Engine) -> None:
        upgrade_schema()
        script = ScriptDirectory.from_config(_alembic_config())
        assert _stamped(engine) == script.get_current_head()

    def test_the_schema_matches_what_the_models_expect(self, engine: Engine) -> None:
        """The check with teeth: every column the ORM will select must exist.

        A migration that creates the tables but misses a column is exactly the
        production failure this module was written for, and it is invisible to
        a test that only asserts the tables are present.
        """
        upgrade_schema()
        for name, table in Base.metadata.tables.items():
            declared = {column.name for column in table.columns}
            missing = declared - _columns(engine, name)
            assert not missing, f"{name} is missing {sorted(missing)}"


def _legacy_database(engine: Engine) -> None:
    """Reproduce a deployment that predates Alembic: the baseline schema, with
    no version table.

    Built by running the baseline migration and then dropping
    ``alembic_version`` — deliberately *not* by ``create_all()`` from the
    current models. ``create_all`` builds today's schema, which already has
    every column that later migrations add, so adopting it replays those
    migrations onto columns that already exist and fails for a reason no real
    deployment can hit. That is a property of the simulation, not of the
    migration, and pinning it to the baseline is what stops every future
    revision from breaking these two tests.
    """
    _run(engine, command.upgrade, BASELINE_REVISION)
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE alembic_version"))


class TestAdoptingAPreMigrationDatabase:
    """The state every existing deployment is in: real data, no version table."""

    def test_a_create_all_database_is_adopted_not_replayed(self, engine: Engine) -> None:
        """Replaying the baseline onto populated tables would fail on the first
        CREATE TABLE, taking the service down on the upgrade that introduced
        migrations — the worst possible moment to find out."""
        _legacy_database(engine)

        upgrade_schema()

        assert "components" in _columns(engine, "run_manifests")

    def test_adoption_applies_every_later_revision(self, engine: Engine) -> None:
        """Not just the one that happened to exist when this was written: an
        adopted database must end up with the same columns as a fresh one."""
        _legacy_database(engine)

        upgrade_schema()

        for name, table in Base.metadata.tables.items():
            declared = {column.name for column in table.columns}
            missing = declared - _columns(engine, name)
            assert not missing, f"{name} is missing {sorted(missing)} after adoption"

    def test_existing_rows_survive_the_adoption(self, engine: Engine) -> None:
        _legacy_database(engine)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO runs (id, status, profile, attested_by, "
                    "attestation_reference, attested_at, llm_enabled, "
                    "retain_plaintext, dynamic_enabled) VALUES "
                    "('r1', 'completed', 'standard', 'kyle', 'SEC-1', "
                    "'2026-01-01 00:00:00', 0, 0, 0)"
                )
            )

        upgrade_schema()

        with engine.connect() as connection:
            assert connection.execute(text("SELECT attested_by FROM runs")).scalar() == "kyle"

    def test_an_empty_database_is_not_mistaken_for_a_legacy_one(self, engine: Engine) -> None:
        """Adoption keys off `runs` existing. Stamping a genuinely empty
        database would skip the baseline and leave it with no tables at all."""
        upgrade_schema()
        assert "runs" in _tables(engine)


class TestIdempotence:
    def test_running_twice_changes_nothing(self, engine: Engine) -> None:
        """Both the API and the workers call this at start-up."""
        upgrade_schema()
        first = _stamped(engine)
        upgrade_schema()
        assert _stamped(engine) == first

    def test_downgrade_then_upgrade_round_trips(self, engine: Engine) -> None:
        upgrade_schema()
        _run(engine, command.downgrade, BASELINE_REVISION)
        assert "components" not in _columns(engine, "run_manifests")
        _run(engine, command.upgrade, "head")
        assert "components" in _columns(engine, "run_manifests")


class TestForeignKeyOrdering:
    """SQLite accepts a `CREATE TABLE` whose foreign key targets a table that
    does not exist yet — it only checks FK targets lazily, never at DDL time.
    Every test above runs against SQLite (by design: no Docker, portable), so
    none of them can see this class of bug.

    Postgres is not so forgiving: it validates a foreign key's target the
    moment the `CREATE TABLE` runs. `0001_baseline` created `artifacts`
    (referencing `runs`) eleven tables before it created `runs` — invisible
    here, and a crash loop on the very first boot of a real deployment. The
    fix is a real cycle, not just a reorder: `artifacts.run_id` points at
    `runs`, and `runs.root_artifact_id` points back at `artifacts`. `runs` is
    now created first without that one column's constraint, and it is closed
    with `ALTER TABLE` once `artifacts` exists — which means the downgrade has
    the same ordering hazard in reverse and needs the same care dropping it.

    These tests render each migration's DDL for the postgresql dialect via
    Alembic's own `--sql` offline mode — real SQL, no database — and replay it
    against the constraint rule Postgres actually enforces, statement by
    statement, in emitted order.
    """

    _CREATE_TABLE = re.compile(r"CREATE TABLE (\w+) \((.*?)\n\);", re.DOTALL)
    _CONSTRAINT_FK = re.compile(r"CONSTRAINT (\w+) FOREIGN KEY\([^)]*\) REFERENCES (\w+)")
    _ALTER_ADD_FK = re.compile(r"ALTER TABLE (\w+) ADD " + _CONSTRAINT_FK.pattern)
    _DROP_TABLE = re.compile(r"DROP TABLE (\w+)")
    _ALTER_DROP_CONSTRAINT = re.compile(r"ALTER TABLE (\w+) DROP CONSTRAINT (\w+)")

    @pytest.fixture
    def offline_sql(self, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
        """(upgrade SQL, downgrade SQL) for the whole revision chain, rendered
        for postgresql regardless of what this environment's own database URL
        happens to be — `env.py` is reloaded fresh per Alembic command, so
        patching the settings function it imports from is enough."""
        import core.config as config_module

        class _FakeSettings:
            database_url = "postgresql+psycopg://x/y"

        monkeypatch.setattr(config_module, "get_settings", lambda: _FakeSettings())

        config = _alembic_config()
        up_buf, down_buf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(up_buf):
            command.upgrade(config, "head", sql=True)
        with contextlib.redirect_stdout(down_buf):
            command.downgrade(config, "head:base", sql=True)
        return up_buf.getvalue(), down_buf.getvalue()

    def test_a_create_table_never_references_a_table_that_does_not_exist_yet(
        self, offline_sql: tuple[str, str]
    ) -> None:
        upgrade_sql, _ = offline_sql
        events: list[tuple[int, str, str, str]] = [
            (m.start(), "create", m.group(1), m.group(2))
            for m in self._CREATE_TABLE.finditer(upgrade_sql)
        ] + [
            (m.start(), "alter_add", m.group(1), m.group(3))
            for m in self._ALTER_ADD_FK.finditer(upgrade_sql)
        ]
        events.sort(key=lambda event: event[0])

        created: set[str] = set()
        for _, kind, first, second in events:
            if kind == "create":
                name, body = first, second
                targets = set(self._CONSTRAINT_FK.findall(body))
                target_tables = {table for _name, table in targets} - {name}
                missing = target_tables - created
                assert not missing, f"CREATE TABLE {name} references {missing} too early"
                created.add(name)
            else:
                from_table, to_table = first, second
                assert from_table in created, f"ALTER TABLE {from_table} before it exists"
                assert to_table in created, f"{from_table} references {to_table} too early"

    def test_a_drop_table_never_leaves_a_dangling_reference_to_it(
        self, offline_sql: tuple[str, str]
    ) -> None:
        upgrade_sql, downgrade_sql = offline_sql

        fk_edges: dict[str, tuple[str, str]] = {}
        for m in self._CREATE_TABLE.finditer(upgrade_sql):
            table, body = m.group(1), m.group(2)
            for name, target in self._CONSTRAINT_FK.findall(body):
                fk_edges[name] = (table, target)
        for m in self._ALTER_ADD_FK.finditer(upgrade_sql):
            fk_edges[m.group(2)] = (m.group(1), m.group(3))

        events: list[tuple[int, str, str, str]] = [
            (m.start(), "drop_table", m.group(1), "")
            for m in self._DROP_TABLE.finditer(downgrade_sql)
        ] + [
            (m.start(), "drop_constraint", m.group(1), m.group(2))
            for m in self._ALTER_DROP_CONSTRAINT.finditer(downgrade_sql)
        ]
        events.sort(key=lambda event: event[0])

        live = set(fk_edges)
        dropped: set[str] = set()
        for _, kind, first, second in events:
            if kind == "drop_constraint":
                assert first == fk_edges[second][0]
                live.discard(second)
            else:
                table = first
                blockers = {
                    name
                    for name in live
                    if fk_edges[name][1] == table
                    and fk_edges[name][0] != table
                    and fk_edges[name][0] not in dropped
                }
                assert not blockers, f"DROP TABLE {table} while {blockers} still reference it"
                dropped.add(table)
                live -= {name for name in live if fk_edges[name][0] == table}
