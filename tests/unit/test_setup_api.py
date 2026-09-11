"""First-run setup, over the real app.

The bootstrap mint moved from a console banner (`api.main._announce_auth`) to
`POST /api/setup/bootstrap` specifically because the banner could only ever be
seen by whichever process won the race to start first, and was gone the moment
it scrolled past. These tests exercise the actual FastAPI app, including
auth's fail-closed dependency stack, to prove the endpoint stays reachable
without a credential and closes itself the instant a token exists.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import core.db as db_module
from api.main import create_app
from core.config import get_settings
from core.models.base import Base


@pytest.fixture(autouse=True)
def _auth_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("BARE_AUTH_REQUIRED", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A real app against a throwaway SQLite database.

    `session_scope()` — what `bootstrap()` uses — reaches `core.db.get_engine`
    directly rather than through FastAPI's dependency injection, so the
    `app.dependency_overrides` swap the other auth tests use would leave it
    pointed at whatever database this process is really configured for.
    Replacing `get_engine` itself, and clearing both its cache and
    `get_sessionmaker`'s, is what makes `session_scope()` and
    `Depends(get_session)` agree on which database they are looking at.
    """
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db_module.get_engine.cache_clear()
    db_module.get_sessionmaker.cache_clear()
    monkeypatch.setattr(db_module, "get_engine", lambda: engine)

    yield TestClient(create_app())

    # `get_engine` itself is what `monkeypatch` restores; only the sessionmaker
    # cache it fed needs clearing by hand, or it outlives this test's engine
    # and the next test to call `get_sessionmaker()` gets a disposed one.
    db_module.get_sessionmaker.cache_clear()
    engine.dispose()


class TestSetupStatus:
    def test_needs_setup_when_no_token_exists(self, client: TestClient) -> None:
        response = client.get("/api/setup/status")
        assert response.status_code == 200
        assert response.json() == {"needs_setup": True}

    def test_does_not_need_setup_once_a_token_exists(self, client: TestClient) -> None:
        client.post("/api/setup/bootstrap")
        assert client.get("/api/setup/status").json() == {"needs_setup": False}

    def test_reachable_with_no_credential(self, client: TestClient) -> None:
        """The one route in the API that must work before any token exists."""
        assert client.get("/api/setup/status").status_code != 401


class TestBootstrap:
    def test_mints_a_token_on_first_call(self, client: TestClient) -> None:
        response = client.post("/api/setup/bootstrap")
        assert response.status_code == 201
        body = response.json()
        assert body["token"].startswith("bare_")
        assert body["name"]

    def test_the_minted_token_actually_authenticates(self, client: TestClient) -> None:
        token = client.post("/api/setup/bootstrap").json()["token"]
        response = client.get("/api/runs", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

    def test_refuses_a_second_call_once_a_token_exists(self, client: TestClient) -> None:
        assert client.post("/api/setup/bootstrap").status_code == 201
        second = client.post("/api/setup/bootstrap")
        assert second.status_code == 409

    def test_is_reachable_with_no_credential(self, client: TestClient) -> None:
        assert client.post("/api/setup/bootstrap").status_code != 401
