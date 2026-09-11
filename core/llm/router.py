"""Role-based model routing.

Different jobs want different models, and on bandwidth-limited hardware the
difference is the whole ballgame. Triage runs over thousands of candidates and
wants a small, fast, non-reasoning model. Explanation runs over a handful of
confirmed findings and can afford a large one.

Config lives in ``config/llm.yaml`` and is hot-reloadable.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.config import EgressPolicy, get_settings
from core.llm.provider import EgressPolicyGuard, LLMProvider, ProviderHealth

log = structlog.get_logger(__name__)

DEFAULT_CONFIG_PATH = Path("config/llm.yaml")

# Providers are few and the work is entirely network wait, so this only
# needs to be large enough that nobody queues behind anybody else.
_MAX_PROBE_WORKERS = 8
ROLES = ("triage", "explain", "remediate", "summarize", "investigate")


class LLMConfigError(ValueError):
    """A configuration that would fail at request time. Raised at load instead.

    An air-gapped deployment must discover it has been pointed at a cloud
    provider when an operator reads the startup logs, not when a scan is
    halfway through.
    """


@dataclass(slots=True)
class LLMConfig:
    enabled: bool
    providers: dict[str, dict[str, Any]]
    roles: dict[str, str]
    egress: EgressPolicy
    redaction: str = "strict"
    allowed_hosts: tuple[str, ...] = ()
    path: Path | None = None

    def provider_for(self, role: str) -> str:
        name = self.roles.get(role)
        if name is None:
            raise LLMConfigError(f"no provider configured for role {role!r}")
        if name not in self.providers:
            raise LLMConfigError(f"role {role!r} points at provider {name!r}, which is not defined")
        return name


def active_config_path() -> Path:
    """Where the live LLM config is read from and written to.

    Not the copy baked into the image. `config/llm.yaml` ships as the *default*,
    but the settings page and the setup wizard write to this file at runtime,
    and an image-local path means every `docker compose build` silently throws
    those edits away — which would make configuring a provider through the UI
    pointless. The runtime copy lives in a volume and is seeded from the image
    default on first use (see `ensure_runtime_config`).
    """
    override = os.environ.get("BARE_LLM_CONFIG")
    if override:
        return Path(override)
    return Path(get_settings().data_dir) / "llm.yaml"


def ensure_runtime_config() -> Path:
    """Seed the runtime config from the image default, and back-fill new roles.

    Copied rather than symlinked so the shipped default stays readable as a
    reference, and so an operator can delete the runtime copy to get it back.

    The back-fill exists because the runtime copy outlives upgrades by design:
    without it, a release that adds a role ships a feature no existing
    deployment can reach, and the only symptom is "no provider is routed to
    'investigate'" on a version where that role is supposed to work.

    Additive only, and conservative with it. An operator's routing is never
    overwritten, and a new role is skipped rather than added when it names a
    provider the runtime config does not define — writing that would make the
    whole config fail to load, which is a far worse upgrade than a missing
    role.
    """
    active = active_config_path()
    packaged = Path(get_settings().repo_root) / DEFAULT_CONFIG_PATH

    if not active.is_file():
        active.parent.mkdir(parents=True, exist_ok=True)
        if packaged.is_file():
            active.write_text(packaged.read_text(encoding="utf-8"), encoding="utf-8")
            log.info("llm.config_seeded", source=str(packaged), target=str(active))
        return active

    if not packaged.is_file():
        return active

    try:
        live = yaml.safe_load(active.read_text(encoding="utf-8")) or {}
        default = yaml.safe_load(packaged.read_text(encoding="utf-8")) or {}
        if not isinstance(live, dict) or not isinstance(default, dict):
            return active

        live_roles = dict(live.get("roles") or {})
        providers = live.get("providers") or {}
        added = {
            role: target
            for role, target in (default.get("roles") or {}).items()
            if role not in live_roles and target in providers
        }
        if added:
            live["roles"] = {**live_roles, **added}
            active.write_text(
                yaml.safe_dump(live, sort_keys=False, allow_unicode=True, width=88),
                encoding="utf-8",
            )
            log.info("llm.config_roles_backfilled", roles=sorted(added))
    except Exception as exc:
        # A malformed runtime config is load_config's problem to report, not
        # something to fail an upgrade over.
        log.warning("llm.config_backfill_skipped", error=str(exc))

    return active


def load_config(path: Path | None = None) -> LLMConfig:
    settings = get_settings()
    config_path = path or ensure_runtime_config()

    if not config_path.is_file():
        # Absent config is not an error: the deterministic pipeline is the
        # default and must work with no model configured at all (§2.5).
        return LLMConfig(
            enabled=False,
            providers={},
            roles={},
            egress=settings.egress_policy,
            path=config_path,
        )

    document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    policy = document.get("policy", {}) or {}
    egress = EgressPolicy(policy.get("egress", settings.egress_policy))

    config = LLMConfig(
        enabled=bool(document.get("enabled", True)),
        providers=document.get("providers", {}) or {},
        roles=document.get("roles", {}) or {},
        egress=egress,
        redaction=policy.get("redaction", "strict"),
        allowed_hosts=tuple(policy.get("allowed_hosts", ()) or ()),
        path=config_path,
    )
    _validate(config, air_gapped=settings.air_gapped)
    return config


def _validate(config: LLMConfig, *, air_gapped: bool) -> None:
    if not config.enabled:
        return

    for role in ROLES:
        if role in config.roles:
            config.provider_for(role)  # raises if the target is undefined

    guard = EgressPolicyGuard(
        allow_egress=config.egress is EgressPolicy.ALLOW,
        air_gapped=air_gapped,
        allowed_hosts=config.allowed_hosts,
    )
    for name, spec in config.providers.items():
        base_url = spec.get("base_url")
        try:
            if base_url:
                guard.check(base_url)
            elif not spec.get("is_local", False):
                # Most LiteLLM providers carry no base URL — the model prefix
                # is what routes, and the library resolves the endpoint itself.
                # Skipping those would mean an air-gapped deployment could hold
                # a working OpenAI provider, which is the whole thing this
                # check exists to prevent.
                guard.check_remote_allowed(f"provider {name!r}")
        except Exception as exc:
            raise LLMConfigError(
                f"provider {name!r} would be blocked by the egress policy: {exc}"
            ) from None


def build_guard(config: LLMConfig) -> EgressPolicyGuard:
    settings = get_settings()
    return EgressPolicyGuard(
        allow_egress=config.egress is EgressPolicy.ALLOW,
        air_gapped=settings.air_gapped,
        allowed_hosts=config.allowed_hosts,
    )


def build_provider(config: LLMConfig, name: str) -> LLMProvider:
    spec = config.providers.get(name)
    if spec is None:
        raise LLMConfigError(f"provider {name!r} is not defined in {config.path}")

    kind = spec.get("kind", "ollama")
    guard = build_guard(config)

    if kind == "ollama":
        from core.llm.providers.ollama import OllamaProvider

        return OllamaProvider(
            model=spec["model"],
            name=name,
            base_url=spec.get("base_url", "http://localhost:11434"),
            guard=guard,
            num_ctx=spec.get("num_ctx"),
        )

    # The key is never read from `spec` — it resolves from the environment or
    # the runtime key store, so it cannot end up in config/llm.yaml, which is
    # a committed file. See core.llm.secrets.
    from core.llm.secrets import resolve_api_key

    api_key = resolve_api_key(name, spec)

    # Everything that is not local Ollama goes through LiteLLM. `kind` is kept
    # as a vendor name in the config because that is what an operator writes,
    # but it selects no code path of its own — the model string carries the
    # provider ("anthropic/claude-...", "gemini/gemini-...") and LiteLLM routes
    # on that.
    from core.llm.providers.litellm_provider import LiteLLMProvider

    base_url = str(spec.get("base_url", "") or "")
    declared_local = spec.get("is_local")

    # Locality decides two things: whether the egress policy permits this
    # provider at all, and whether plaintext could ever be sent to it. Prefer
    # the URL when there is one, since that is checkable; fall back to what the
    # catalog declared; default to "hosted", which is the safe direction.
    if base_url:
        is_local_endpoint = guard.is_local(base_url)
    elif declared_local is not None:
        is_local_endpoint = bool(declared_local)
    else:
        is_local_endpoint = False

    # The air-gap guarantee, enforced where it is absolute: a hosted provider
    # is never constructed under a deny policy, so there is no request for
    # LiteLLM to route. It has no single interceptable choke point — measured,
    # not assumed; see the module docstring — so this is the check that counts.
    if not is_local_endpoint:
        guard.check_remote_allowed(f"provider {name!r} ({kind})")

    return LiteLLMProvider(
        model=spec["model"],
        name=name,
        base_url=base_url,
        api_key=api_key,
        guard=guard,
        is_local_endpoint=is_local_endpoint,
    )


def provider_for_role(role: str, config: LLMConfig | None = None) -> LLMProvider:
    config = config or load_config()
    if not config.enabled:
        raise LLMConfigError("the LLM layer is disabled")
    return build_provider(config, config.provider_for(role))


def probe_provider(config: LLMConfig, name: str) -> ProviderHealth:
    """Probe one provider, turning any failure into an unhealthy result.

    A provider that cannot even be *built* — an unknown kind, a malformed spec
    — is as unhealthy as one that will not answer, and the settings page needs
    to render either way.
    """
    try:
        return build_provider(config, name).health()
    except Exception as exc:
        return ProviderHealth(healthy=False, provider=name, detail=str(exc)[:300])


def health_check_all(config: LLMConfig | None = None) -> dict[str, ProviderHealth]:
    """Probe every configured provider. Drives the settings page.

    Concurrently, because these are independent network waits and the page
    blocks on all of them. Serially, two unreachable providers cost the sum of
    their timeouts; the settings page took the better part of a minute to
    render against hosts that were simply not there.
    """
    config = config or load_config()
    names = sorted(config.providers)
    if not names:
        return {}

    with ThreadPoolExecutor(max_workers=min(len(names), _MAX_PROBE_WORKERS)) as pool:
        return dict(zip(names, pool.map(lambda n: probe_provider(config, n), names), strict=True))
