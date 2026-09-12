"""Settings: LLM provider configuration and live connection testing."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.deps import require_scope
from api.schemas.models import LlmSettingsOut, ProviderHealthOut
from core.auth import Scope
from core.config import EgressPolicy
from core.llm import LLMConfigError, build_provider, load_config
from core.llm.router import health_check_all
from core.llm.settings_writer import LlmUpdate, apply_update
from core.rules import load_rule_pack

router = APIRouter(
    prefix="/api/settings",
    tags=["settings"],
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)


@router.get("/llm", response_model=LlmSettingsOut)
def get_llm_settings() -> LlmSettingsOut:
    """Current LLM configuration with a live health probe per provider.

    Probing on read rather than caching: "test connection" is the question
    being asked, and a stale green tick is worse than no tick.
    """
    try:
        config = load_config()
    except LLMConfigError as exc:
        # A config that would fail at request time fails here instead, which is
        # the whole point of validating at load (§8.2).
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from None

    # Concurrently: the page blocks on every provider, and these are pure
    # network waits. Probed serially, two unreachable hosts cost the sum of
    # their timeouts before anything renders.
    health_by_name = health_check_all(config)

    providers: list[ProviderHealthOut] = []
    for name in sorted(config.providers):
        health = health_by_name[name]
        try:
            is_local = build_provider(config, name).is_local
        except Exception:
            # Already reported as unhealthy by the probe; locality is unknown
            # for a provider that cannot be constructed.
            is_local = False
        providers.append(
            ProviderHealthOut(
                name=name,
                healthy=health.healthy,
                model=health.model,
                detail=health.detail,
                latency_s=health.latency_s,
                is_local=is_local,
                available_models=list(health.available_models),
            )
        )

    return LlmSettingsOut(
        enabled=config.enabled,
        egress=str(config.egress),
        redaction=config.redaction,
        roles=config.roles,
        providers=providers,
        config_path=str(config.path) if config.path else None,
    )


@router.get("/rules")
def get_rule_pack() -> dict[str, object]:
    """The loaded rule pack. Its hash is what the run manifest records."""
    from pathlib import Path

    from core.config import get_settings

    try:
        pack = load_rule_pack(Path(get_settings().repo_root) / "detections")
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from None

    return {
        "version": pack.version,
        "hash": pack.hash,
        "rule_count": len(pack.enabled_rules()),
        "false_positive_corpus_size": len(pack.false_positives),
        "rules": [
            {
                "id": rule.id,
                "name": rule.name,
                "category": rule.category,
                "severity": str(rule.severity),
                "confidence": rule.confidence,
                "cwe": rule.cwe,
                "description": rule.description,
                "tags": list(rule.tags),
            }
            for rule in pack.enabled_rules()
        ],
    }


class LlmSettingsUpdate(BaseModel):
    """A change from the settings page.

    Every field optional so the console sends only what the operator touched;
    an absent field is "leave it alone", not "clear it".
    """

    enabled: bool | None = None
    roles: dict[str, str] | None = Field(default=None, description="Role name to provider name.")
    provider_models: dict[str, str] | None = Field(
        default=None, description="Provider name to model id."
    )


@router.put("/llm", response_model=LlmSettingsOut)
def update_llm_settings(update: LlmSettingsUpdate) -> LlmSettingsOut:
    """Write the change to config/llm.yaml, then report the live state.

    The file is hot-reloaded, so the next scan picks this up with no restart.
    Returning the freshly probed settings rather than an acknowledgement means
    the console cannot show a model it failed to select.
    """
    try:
        apply_update(
            LlmUpdate(
                enabled=update.enabled,
                roles=update.roles,
                provider_models=update.provider_models,
            )
        )
    except LLMConfigError as exc:
        # 422: the request was well-formed, the resulting config would not load.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, f"could not write the config: {exc}"
        ) from None

    return get_llm_settings()


class CatalogEntryOut(BaseModel):
    id: str
    label: str
    kind: str
    base_url: str
    default_model: str
    requires_key: bool
    is_local: bool
    summary: str
    key_hint: str
    key_url: str
    suggested_models: list[str]
    needs_base_url: bool


@router.get("/llm/catalog", response_model=list[CatalogEntryOut])
def llm_catalog() -> list[CatalogEntryOut]:
    """The providers the setup wizard offers.

    Served from the backend rather than hardcoded in the dashboard so that the
    list and the adapters that implement it cannot drift: every entry's `kind`
    is one `build_provider` actually knows.
    """
    from core.llm.catalog import CATALOG

    return [
        CatalogEntryOut(
            id=entry.id,
            label=entry.label,
            kind=entry.kind,
            base_url=entry.base_url,
            default_model=entry.default_model,
            requires_key=entry.requires_key,
            is_local=entry.is_local,
            summary=entry.summary,
            key_hint=entry.key_hint,
            key_url=entry.key_url,
            suggested_models=list(entry.suggested_models),
            needs_base_url=entry.needs_base_url,
        )
        for entry in CATALOG
    ]


class ConnectProviderRequest(BaseModel):
    catalog_id: str = Field(description="An id from GET /api/settings/llm/catalog.")
    model: str
    base_url: str | None = None
    api_key: str | None = None
    name: str | None = Field(
        default=None, description="Provider name in the config; defaults to catalog_id."
    )
    assign_roles: list[str] | None = Field(
        default=None,
        description="Roles to point at this provider. Defaults to every editable role.",
    )


class ConnectProviderResponse(BaseModel):
    name: str
    health: ProviderHealthOut
    settings: LlmSettingsOut


@router.post("/llm/providers", response_model=ConnectProviderResponse)
def connect_provider(request: ConnectProviderRequest) -> ConnectProviderResponse:
    """Define a provider, store its key, verify it, and route roles to it.

    The key is written to the runtime key store, never to config/llm.yaml —
    that file is committed, and a provider key in it is a credential in the
    repository. See `core.llm.secrets`.

    The connection is tested *before* the config is written, so a wizard that
    says "connected" means it. A provider that cannot be reached is a 422 with
    the reason, and nothing has changed on disk.
    """
    from core.llm.catalog import BY_ID
    from core.llm.secrets import forget_api_key, set_api_key
    from core.llm.settings_writer import EDITABLE_ROLES, NewProvider

    entry = BY_ID.get(request.catalog_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown provider {request.catalog_id!r}")

    name = (request.name or entry.id).strip()
    base_url = (request.base_url or entry.base_url).strip()
    model = request.model.strip()

    if not model:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "a model is required")
    if entry.requires_key and not (request.api_key or "").strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"{entry.label} requires an API key"
        )
    # Most providers need no base URL — LiteLLM knows where they live, and the
    # model prefix is what routes. Only the self-hosted and bring-your-own
    # endpoints genuinely require one.
    if entry.needs_base_url and not base_url:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{entry.label} needs a base URL; there is no default for it",
        )

    # Stored before the probe because the adapter resolves its key from the
    # store, not from this request. Rolled back below if the probe fails, so a
    # rejected key is not left behind.
    had_key_before = False
    if (request.api_key or "").strip():
        from core.llm.secrets import has_api_key

        had_key_before = has_api_key(name, {})
        set_api_key(name, request.api_key.strip())

    # `is_local` is recorded so the egress decision does not depend on being
    # able to parse a URL: most LiteLLM providers have none in the config, and
    # a hosted provider with no URL must still be refused under a deny policy.
    spec: dict[str, object] = {
        "kind": entry.kind,
        "model": model,
        "is_local": entry.is_local,
    }
    if base_url:
        spec["base_url"] = base_url
    probe_config = load_config()
    probe_config.providers[name] = spec
    if not entry.is_local:
        # A hosted endpoint is blocked by the default deny policy, so probe it
        # under the policy it will actually run with rather than reporting a
        # guard rejection as an unreachable host.
        probe_config.egress = EgressPolicy.ALLOW

    try:
        health = build_provider(probe_config, name).health()
    except Exception as exc:
        if not had_key_before:
            forget_api_key(name)
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"could not reach {entry.label}: {exc}"
        ) from None

    if not health.healthy:
        if not had_key_before:
            forget_api_key(name)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, health.detail)

    roles = request.assign_roles if request.assign_roles is not None else list(EDITABLE_ROLES)
    unknown = [r for r in roles if r not in EDITABLE_ROLES]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"unknown role(s): {unknown}")

    try:
        apply_update(
            LlmUpdate(
                enabled=True,
                add_provider=NewProvider(
                    name=name,
                    kind=entry.kind,
                    model=model,
                    base_url=base_url,
                    is_local=entry.is_local,
                ),
                roles={role: name for role in roles},
                egress=None if entry.is_local else "allow",
            )
        )
    except LLMConfigError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    except OSError as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, f"could not write the config: {exc}"
        ) from None

    return ConnectProviderResponse(
        name=name,
        health=ProviderHealthOut(
            name=name,
            healthy=health.healthy,
            model=health.model,
            detail=health.detail,
            latency_s=health.latency_s,
            is_local=entry.is_local,
            available_models=list(health.available_models),
        ),
        settings=get_llm_settings(),
    )
