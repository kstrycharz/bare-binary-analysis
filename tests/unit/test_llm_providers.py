"""Provider configuration, the API key store, and the egress guarantee.

Two things are being pinned here, and the second is the one that matters.

**Keys must never reach `config/llm.yaml`.** That file is committed, so a
provider key in it is a credential in the repository — the exact failure this
product exists to find in other people's artifacts.

**A hosted provider must be unreachable under a deny policy.** Since everything
except local Ollama now routes through LiteLLM, this cannot be enforced at the
HTTP call: LiteLLM has no single choke point. Measured, not assumed —
`litellm.client_session` catches the OpenAI family and nothing else, and an
explicit `api_base` is honoured by Anthropic but ignored by Gemini. So the
guarantee lives at construction and at config load, where it is absolute: a
non-local provider is never built, so there is no request to intercept. These
tests are what hold that line.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from core.config import EgressPolicy
from core.llm import secrets
from core.llm.catalog import BY_ID, CATALOG
from core.llm.provider import EgressBlocked, EgressPolicyGuard
from core.llm.providers.litellm_provider import LiteLLMProvider, _explain_failure
from core.llm.router import LLMConfig, LLMConfigError, build_provider
from core.llm.settings_writer import LlmUpdate, NewProvider, apply_update

KEY = "sk-not-a-real-key-0123456789"


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "llm-keys.json"
    monkeypatch.setenv("BARE_LLM_KEY_STORE", str(path))
    yield path


def _config(egress: EgressPolicy = EgressPolicy.DENY, **spec: object) -> LLMConfig:
    return LLMConfig(
        enabled=True,
        providers={"p": dict(spec)},
        roles={},
        egress=egress,
        path=Path("llm.yaml"),
    )


class TestTheAirGapHolds:
    """The guarantee, at the level where LiteLLM cannot undermine it."""

    def test_a_hosted_provider_cannot_be_built_under_deny(self) -> None:
        """No URL to check, and none needed: the provider is refused outright,
        so LiteLLM never gets a request to route."""
        config = _config(model="gpt-4o-mini", kind="openai", is_local=False)
        with pytest.raises(EgressBlocked, match="deny"):
            build_provider(config, "p")

    def test_a_provider_with_no_locality_declared_is_treated_as_hosted(self) -> None:
        """The safe direction. A config that forgot to say gets refused rather
        than quietly permitted."""
        config = _config(model="gpt-4o-mini", kind="openai")
        with pytest.raises(EgressBlocked):
            build_provider(config, "p")

    def test_a_local_endpoint_is_permitted_under_deny(self) -> None:
        """An Ollama or vLLM box on the LAN is not egress in any sense a
        security team cares about."""
        config = _config(model="hosted_vllm/x", kind="vllm", base_url="http://192.168.1.50:8000/v1")
        provider = build_provider(config, "p")
        assert provider.is_local is True

    def test_a_hosted_provider_builds_once_egress_is_allowed(self) -> None:
        config = _config(EgressPolicy.ALLOW, model="gpt-4o-mini", kind="openai", is_local=False)
        provider = build_provider(config, "p")
        assert provider.is_local is False

    def test_air_gapped_refuses_even_when_egress_is_allowed(self) -> None:
        """`air_gapped` is a separate switch from the egress policy, and it
        wins."""
        guard = EgressPolicyGuard(allow_egress=True, air_gapped=True)
        with pytest.raises(EgressBlocked, match="air-gapped"):
            guard.check_remote_allowed("provider 'p'")

    def test_a_url_that_claims_to_be_local_but_is_not_is_still_refused(self) -> None:
        """Locality is decided from the URL when there is one, not from what
        the config asserts — otherwise `is_local: true` would be a bypass."""
        config = _config(
            model="gpt-4o-mini",
            kind="openai",
            base_url="https://api.openai.com/v1",
            is_local=True,
        )
        with pytest.raises(EgressBlocked):
            build_provider(config, "p")


class TestConfigLoadRefusesTheSameThing:
    """Start-up must fail on a config that would be blocked at request time,
    so an operator finds out from the logs rather than mid-scan."""

    def test_a_hosted_provider_without_a_url_is_caught_at_load(self, tmp_path: Path) -> None:
        config = tmp_path / "llm.yaml"
        config.write_text(
            yaml.safe_dump({"enabled": True, "providers": {}, "roles": {}}),
            encoding="utf-8",
        )
        with pytest.raises(LLMConfigError, match="egress"):
            apply_update(
                LlmUpdate(
                    add_provider=NewProvider(
                        name="openai", kind="openai", model="gpt-4o-mini", is_local=False
                    )
                ),
                path=config,
            )
        # Nothing was written.
        assert yaml.safe_load(config.read_text(encoding="utf-8"))["providers"] == {}


class TestKeysStayOutOfTheConfig:
    def test_a_new_provider_writes_no_key_into_the_yaml(self, tmp_path: Path) -> None:
        """The single most important property here."""
        config = tmp_path / "llm.yaml"
        config.write_text(
            yaml.safe_dump({"enabled": True, "providers": {}, "roles": {}}),
            encoding="utf-8",
        )

        apply_update(
            LlmUpdate(
                add_provider=NewProvider(
                    name="openai", kind="openai", model="gpt-4o-mini", is_local=False
                ),
                egress="allow",
            ),
            path=config,
        )

        text = config.read_text(encoding="utf-8")
        assert KEY not in text
        assert "api_key" not in text
        assert "gpt-4o-mini" in text

    def test_the_store_holds_the_key_not_the_config(self, store: Path) -> None:
        secrets.set_api_key("openai", KEY)
        assert secrets.resolve_api_key("openai", {}) == KEY
        assert KEY in store.read_text(encoding="utf-8")

    def test_an_env_var_wins_over_the_store(
        self, store: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real deployment injects the key like every other secret; the store
        exists only so the wizard does not require hand-editing files."""
        secrets.set_api_key("openai", "from-store")
        monkeypatch.setenv("MY_OPENAI_KEY", "from-env")
        assert secrets.resolve_api_key("openai", {"api_key_env": "MY_OPENAI_KEY"}) == "from-env"

    def test_an_empty_env_var_falls_through_to_the_store(
        self, store: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exported-but-blank variable is the usual shape of a broken
        deployment; treating it as configured would mean sending no key."""
        secrets.set_api_key("openai", "from-store")
        monkeypatch.setenv("MY_OPENAI_KEY", "   ")
        assert secrets.resolve_api_key("openai", {"api_key_env": "MY_OPENAI_KEY"}) == "from-store"

    def test_a_missing_store_is_not_an_error(self, store: Path) -> None:
        assert secrets.resolve_api_key("openai", {}) is None

    def test_a_corrupt_store_does_not_raise(self, store: Path) -> None:
        store.write_text("{ not json", encoding="utf-8")
        assert secrets.resolve_api_key("openai", {}) is None

    def test_forgetting_a_key_removes_it(self, store: Path) -> None:
        secrets.set_api_key("openai", KEY)
        assert secrets.forget_api_key("openai") is True
        assert secrets.resolve_api_key("openai", {}) is None
        assert KEY not in store.read_text(encoding="utf-8")


class TestKeysStayOutOfErrors:
    """An error string reaches the settings page and the logs."""

    def test_a_key_is_scrubbed_from_a_provider_error(self) -> None:
        exc = RuntimeError(f"401 Unauthorized for key {KEY}")
        assert KEY not in _explain_failure(exc, KEY)

    def test_the_failure_is_named_not_just_echoed(self) -> None:
        """LiteLLM normalises vendor errors into typed exceptions, which is one
        of the reasons to use it: "your key is wrong" and "no such model" are
        different problems with different fixes."""

        class AuthenticationError(Exception):
            pass

        assert "key was rejected" in _explain_failure(AuthenticationError("nope"), None)


class TestLocality:
    """`is_local` is what the redaction layer keys off, so it is keyed to the
    endpoint rather than to the vendor: a vLLM box on the LAN is local, and
    api.openai.com never is."""

    def test_a_lan_endpoint_is_local(self) -> None:
        provider = LiteLLMProvider(
            model="hosted_vllm/x",
            base_url="http://192.168.1.50:8000/v1",
            guard=EgressPolicyGuard(allow_egress=True),
        )
        assert provider.is_local is True

    def test_a_hosted_endpoint_is_not(self) -> None:
        provider = LiteLLMProvider(
            model="gpt-4o-mini",
            base_url="https://api.openai.com/v1",
            guard=EgressPolicyGuard(allow_egress=True),
        )
        assert provider.is_local is False

    def test_no_url_and_no_declaration_defaults_to_hosted(self) -> None:
        """The safe direction: this flag gates whether plaintext could ever be
        sent, so an unknown must not read as local."""
        provider = LiteLLMProvider(model="gpt-4o-mini", guard=EgressPolicyGuard(allow_egress=True))
        assert provider.is_local is False


class TestCatalogMatchesLiteLLM:
    def test_every_hosted_entry_declares_it_needs_a_key(self) -> None:
        for entry in CATALOG:
            if not entry.is_local:
                assert entry.requires_key or entry.id == "custom", entry.id

    def test_ids_are_unique(self) -> None:
        assert len(BY_ID) == len(CATALOG)

    def test_every_default_model_routes_to_the_provider_it_claims(self) -> None:
        """A model string that only looks right is a wizard entry that fails at
        the first call. LiteLLM's own resolver is the authority."""
        from core.llm.providers.litellm_provider import resolve_provider

        # Entries whose default is a placeholder for the operator to complete.
        placeholders = {"vllm", "azure", "litellm-proxy", "custom"}
        for entry in CATALOG:
            if entry.id in placeholders or entry.kind == "ollama":
                continue
            assert resolve_provider(entry.default_model), entry.id


class TestTheRuntimeConfigOutlivesARebuild:
    """Everything under `repo_root` is baked into the image, so a config the
    wizard wrote there would be discarded by the next `docker compose build` —
    silently, taking the operator's provider choice with it."""

    def _env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, packaged: dict, live: dict | None
    ) -> Path:
        from core.config import get_settings

        repo = tmp_path / "repo"
        (repo / "config").mkdir(parents=True)
        (repo / "config" / "llm.yaml").write_text(yaml.safe_dump(packaged), encoding="utf-8")
        data = tmp_path / "data"
        data.mkdir()
        if live is not None:
            (data / "llm.yaml").write_text(yaml.safe_dump(live), encoding="utf-8")

        monkeypatch.setenv("BARE_DATA_DIR", str(data))
        monkeypatch.setenv("BARE_REPO_ROOT", str(repo))
        monkeypatch.delenv("BARE_LLM_CONFIG", raising=False)
        get_settings.cache_clear()
        return data

    def test_the_live_config_is_not_the_packaged_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from core.config import get_settings
        from core.llm.router import active_config_path

        self._env(tmp_path, monkeypatch, {"enabled": False}, None)
        active = active_config_path()
        assert (tmp_path / "repo") not in active.parents
        assert (tmp_path / "data") in active.parents
        get_settings.cache_clear()

    def test_an_operator_edit_is_never_clobbered_by_reseeding(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from core.config import get_settings
        from core.llm.router import ensure_runtime_config

        self._env(
            tmp_path,
            monkeypatch,
            {"providers": {"local": {"kind": "ollama", "model": "shipped"}}, "roles": {}},
            {"providers": {"local": {"kind": "ollama", "model": "operator-choice"}}, "roles": {}},
        )
        merged = yaml.safe_load(ensure_runtime_config().read_text(encoding="utf-8"))
        assert merged["providers"]["local"]["model"] == "operator-choice"
        get_settings.cache_clear()

    def test_a_role_added_by_an_upgrade_reaches_an_existing_deployment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without a back-fill, a release that adds a role ships a feature no
        existing deployment can reach, and the only symptom is "no provider is
        routed to 'investigate'" on a version where it is supposed to work."""
        from core.config import get_settings
        from core.llm.router import ensure_runtime_config

        self._env(
            tmp_path,
            monkeypatch,
            {
                "providers": {"local": {"kind": "ollama", "model": "m"}},
                "roles": {"triage": "local", "investigate": "local"},
            },
            {
                "providers": {"local": {"kind": "ollama", "model": "operator-choice"}},
                "roles": {"triage": "local"},
            },
        )
        merged = yaml.safe_load(ensure_runtime_config().read_text(encoding="utf-8"))
        assert merged["roles"]["investigate"] == "local"
        assert merged["providers"]["local"]["model"] == "operator-choice"
        get_settings.cache_clear()

    def test_a_new_role_naming_an_unknown_provider_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Writing it would make the whole config fail to load — a far worse
        upgrade than a missing role."""
        from core.config import get_settings
        from core.llm.router import ensure_runtime_config

        self._env(
            tmp_path,
            monkeypatch,
            {"roles": {"investigate": "a-provider-they-renamed"}},
            {"providers": {"mine": {"kind": "ollama", "model": "m"}}, "roles": {}},
        )
        merged = yaml.safe_load(ensure_runtime_config().read_text(encoding="utf-8"))
        assert "investigate" not in (merged.get("roles") or {})
        get_settings.cache_clear()
