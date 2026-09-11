"""Where a cloud provider's API key lives.

Deliberately *not* ``config/llm.yaml``. That file is committed — it carries the
role routing and model names, and its git history is useful. A provider key in
it is a credential in the repository, which is precisely the failure this
product exists to find in other people's artifacts.

So keys resolve in this order:

1. **An environment variable** named by the provider spec's ``api_key_env``.
   The right answer for a real deployment: the key comes from the orchestrator
   the same way every other secret does, and never touches disk here.
2. **The runtime key store** — a 0600 JSON file in a Docker volume, written by
   the setup wizard. This exists so that "paste your key into the browser once"
   works without asking an operator to hand-edit a file and restart the stack.

Nothing writes a key back into ``config/llm.yaml``, and nothing logs one.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

KEY_STORE_NAME = "llm-keys.json"


def key_store_path() -> Path:
    """Overridable so tests and host-run processes do not fight over /app.

    Defaults under `Settings.data_dir` — the same volume the live LLM config
    uses — so a key configured through the wizard survives a rebuild.
    """
    override = os.environ.get("BARE_LLM_KEY_STORE")
    if override:
        return Path(override)

    from core.config import get_settings

    return Path(get_settings().data_dir) / KEY_STORE_NAME


def _read_store() -> dict[str, str]:
    path = key_store_path()
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as exc:
        # A corrupt store must not take the stack down: the deterministic
        # pipeline does not need a model at all.
        log.warning("llm.key_store_unreadable", error=str(exc))
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def resolve_api_key(provider_name: str, spec: dict[str, Any]) -> str | None:
    """The key for one provider, or None if it has none configured."""
    env_name = spec.get("api_key_env")
    if env_name:
        from_env = os.environ.get(str(env_name), "").strip()
        if from_env:
            return from_env

    stored = _read_store().get(provider_name, "").strip()
    return stored or None


def set_api_key(provider_name: str, api_key: str) -> None:
    """Persist a key for one provider, 0600, replacing any previous value."""
    path = key_store_path()
    store = _read_store()
    store[provider_name] = api_key

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    # Windows bind mounts do not carry POSIX modes. The file lives in a
    # container volume in every real deployment, so failing the write here
    # would be worse than proceeding without the mode.
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    # The provider name only. Never the key, not even a prefix — unlike an API
    # token we minted, this one belongs to a third party and we have no claim
    # to put any part of it in a log aggregator.
    log.info("llm.api_key_stored", provider=provider_name)


def forget_api_key(provider_name: str) -> bool:
    store = _read_store()
    if provider_name not in store:
        return False
    del store[provider_name]
    path = key_store_path()
    path.write_text(json.dumps(store, indent=2, sort_keys=True), encoding="utf-8")
    log.info("llm.api_key_forgotten", provider=provider_name)
    return True


def has_api_key(provider_name: str, spec: dict[str, Any]) -> bool:
    return resolve_api_key(provider_name, spec) is not None
