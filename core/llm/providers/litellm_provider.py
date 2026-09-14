"""LiteLLM adapter — one transport, a hundred-odd providers.

Replaces the hand-written OpenAI/Anthropic/Google adapters. The maintenance
argument is straightforward: every vendor changes its wire format eventually,
and tracking that across a growing list is not this project's job.

**How egress is enforced, and why it is not where you would expect.**

LiteLLM has no single choke point. Measured, not assumed: setting
``litellm.client_session`` to an httpx client with a request hook catches the
OpenAI family and *nothing else* — Anthropic, Gemini, and Groq route through
their own handlers and never touch it. Explicit ``api_base`` is honoured by
Anthropic but ignored by Gemini. So neither mechanism can carry the air-gap
guarantee on its own.

The guarantee therefore lives one level up, where it is absolute: **a provider
whose endpoint is not local cannot be constructed at all under a deny policy.**
`build_provider` checks locality before this class is instantiated, and
`load_config` refuses the whole config at startup. An air-gapped deployment
cannot hold a hosted provider, so there is no request for LiteLLM to route.

Everything below is defence in depth on top of that: the `api_base` check where
we have one, the client-session hook for the providers that honour it, and
telemetry off.
"""

from __future__ import annotations

import os
from typing import Any

import structlog

from core.llm.provider import (
    DEFAULT_TIMEOUT_S,
    HEALTH_TIMEOUT_S,
    Capabilities,
    Completion,
    EgressPolicyGuard,
    LLMProvider,
    Message,
    ProviderHealth,
    timed,
)

log = structlog.get_logger(__name__)


def _configure_litellm() -> Any:
    """Import LiteLLM with the settings this product requires.

    Idempotent, and done on first use rather than at import time: the module is
    heavy, and a deployment with no model configured must not pay for it.
    """
    import litellm

    # No phoning home from a tool whose selling point is that artifacts never
    # leave the network.
    litellm.telemetry = False
    litellm.suppress_debug_info = True
    # Retries are the caller's decision here. An advisory role that silently
    # retries three times turns a 20-second explain into a minute with no
    # indication why.
    litellm.num_retries = 0
    return litellm


class LiteLLMProvider(LLMProvider):
    """Any model LiteLLM can reach, addressed as ``provider/model``."""

    kind = "litellm"

    def __init__(
        self,
        *,
        model: str,
        name: str = "litellm",
        base_url: str = "",
        api_key: str | None = None,
        guard: EgressPolicyGuard | None = None,
        is_local_endpoint: bool | None = None,
        context_window: int = 128_000,
        max_output_tokens: int = 8192,
    ) -> None:
        super().__init__(
            model=model,
            name=name,
            guard=guard or EgressPolicyGuard(allow_egress=False),
        )
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._context_window = context_window
        self._max_output_tokens = max_output_tokens
        # Declared by the catalog. Falls back to inspecting the URL, and to
        # False when there is no URL to inspect — the safe direction, since
        # this flag is what the redaction layer keys off to decide whether
        # plaintext could ever be sent.
        if is_local_endpoint is not None:
            self._is_local = is_local_endpoint
        elif self.base_url:
            self._is_local = self._guard.is_local(self.base_url)
        else:
            self._is_local = False

    @property
    def is_local(self) -> bool:
        return self._is_local

    def _kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"model": self.model}
        if self.base_url:
            kwargs["api_base"] = self.base_url
        if self._api_key:
            kwargs["api_key"] = self._api_key
        return kwargs

    def _check_egress(self) -> None:
        """Re-check at the call, on top of the construction-time refusal.

        Only meaningful when we have a URL; when we do not, the locality flag
        from the catalog is what stands, and that was already enforced before
        this object existed.
        """
        if self.base_url:
            self._guard.check(self.base_url)
        elif not self._is_local:
            self._guard.check_remote_allowed(self.model)

    def complete(
        self,
        messages: list[Message],
        *,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> Completion:
        litellm = _configure_litellm()
        self._check_egress()

        kwargs = self._kwargs()
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        started = timed()
        response = litellm.completion(
            messages=[{"role": m.role, "content": m.content} for m in messages],
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout_s,
            **kwargs,
        )
        duration = timed() - started

        choice = response.choices[0]
        message = choice.message
        text = (getattr(message, "content", None) or "").strip()

        # Reasoning models put their deliberation here and leave `content`
        # empty until it finishes. Carried under the same key the Ollama
        # adapter uses so the "spent its budget thinking" diagnosis in
        # core/llm/explain.py works identically for every provider.
        thinking = (getattr(message, "reasoning_content", None) or "").strip()

        usage = getattr(response, "usage", None)
        return Completion(
            text=text,
            model=getattr(response, "model", None) or self.model,
            prompt_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            completion_tokens=getattr(usage, "completion_tokens", None) if usage else None,
            duration_s=round(duration, 3),
            raw={"thinking": thinking} if thinking else {},
        )

    def capabilities(self) -> Capabilities:
        litellm = _configure_litellm()

        context_window = self._context_window
        max_output = self._max_output_tokens
        structured = True
        try:
            info = litellm.get_model_info(self.model)
            context_window = int(info.get("max_input_tokens") or context_window)
            max_output = int(info.get("max_output_tokens") or max_output)
            structured = bool(info.get("supports_response_schema", True))
        except Exception as exc:
            # An unknown model is not an error: LiteLLM's cost map does not
            # cover self-hosted or brand-new models, and both work fine.
            log.debug("litellm.model_info_unavailable", model=self.model, error=str(exc))

        return Capabilities(
            native_tool_calling=True,
            structured_output=structured,
            context_window=context_window,
            max_output_tokens=max_output,
        )

    def health(self, *, timeout_s: float = HEALTH_TIMEOUT_S) -> ProviderHealth:
        """Probe with a real one-token completion.

        There is no uniform "list models" across LiteLLM's providers, and a
        reachability check that does not exercise the credential would report
        healthy for a key that cannot actually call the model — which is the
        failure an operator most needs to catch during setup.
        """
        try:
            self._check_egress()
        except Exception as exc:
            return ProviderHealth(healthy=False, provider=self.name, detail=str(exc))

        if not self._api_key and not self._is_local:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail="no API key configured for this provider",
            )

        litellm = _configure_litellm()
        try:
            started = timed()
            litellm.completion(
                messages=[{"role": "user", "content": "ok"}],
                max_tokens=1,
                timeout=timeout_s,
                **self._kwargs(),
            )
            latency = timed() - started
        except Exception as exc:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail=_explain_failure(exc, self._api_key),
            )

        return ProviderHealth(
            healthy=True,
            provider=self.name,
            model=self.model,
            detail="reachable, and the credential works",
            latency_s=round(latency, 3),
            available_models=self._list_models(timeout_s),
        )

    def _list_models(self, timeout_s: float) -> tuple[str, ...]:
        """Best-effort model listing for OpenAI-compatible endpoints.

        vLLM, LM Studio, and every LiteLLM proxy answer `GET /models` on the
        base URL, and those are precisely the providers an operator picks
        models *from* on the settings page. Hosted vendors with no base URL
        have no such route, and guessing at api.litellm.ai-style endpoints
        would send traffic somewhere the egress policy never approved — so
        this only ever runs when we already hold a URL, and a failure to list
        is invisible: reachability and the credential were just proven by the
        completion above.
        """
        if not self.base_url:
            return ()
        import httpx

        try:
            headers = {"authorization": f"Bearer {self._api_key}"} if self._api_key else {}
            response = httpx.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=timeout_s,
                follow_redirects=False,
            )
            response.raise_for_status()
            data = response.json()
            models = tuple(str(entry["id"]) for entry in data.get("data", []) if entry.get("id"))
        except Exception:
            return ()
        # Prefix them the way LiteLLM routes: `hosted_vllm/qwen3.8-flash-next`
        # is what `provider_models` needs written back, not the bare id.
        prefix = self.model.split("/", 1)[0] if "/" in self.model else ""
        return tuple(f"{prefix}/{m}" if prefix else m for m in models)


def _explain_failure(exc: Exception, api_key: str | None) -> str:
    """Turn a provider exception into something an operator can act on.

    LiteLLM normalises errors into typed exceptions, which is one of the
    reasons to use it: "your key is wrong" and "that model does not exist" are
    different problems with different fixes, and every vendor words them
    differently.
    """
    name = type(exc).__name__
    text = str(exc)
    if api_key and api_key in text:
        # A key in an error string reaches the settings page and the logs.
        text = text.replace(api_key, "***")

    hint = {
        "AuthenticationError": "the API key was rejected",
        "NotFoundError": "the model was not found for this key",
        "RateLimitError": "rate limited — the key works, but the provider is throttling",
        "APIConnectionError": "could not reach the endpoint",
        "Timeout": "the endpoint did not respond in time",
        "BadRequestError": "the provider rejected the request",
    }.get(name)

    return f"{hint}: {text[:300]}" if hint else text[:400]


def resolve_provider(model: str) -> str:
    """LiteLLM's own name for whatever `model` addresses.

    Used by the catalog test to prove every entry is something LiteLLM can
    actually route, rather than a string that only looks right.
    """
    litellm = _configure_litellm()
    # Via the module rather than a `from` import: LiteLLM re-exports this
    # without declaring it in `__all__`, so a direct import fails mypy strict.
    _model, provider, _key, _base = litellm.get_llm_provider(model)
    return str(provider)


def default_api_key_env(provider: str) -> str:
    """The environment variable LiteLLM itself reads for a provider."""
    return f"{provider.upper().replace('-', '_')}_API_KEY"


def key_is_in_environment(provider: str) -> bool:
    return bool(os.environ.get(default_api_key_env(provider), "").strip())
