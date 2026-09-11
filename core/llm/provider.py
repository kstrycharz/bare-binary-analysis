"""Provider abstraction and egress enforcement.

The trust boundary lives here. Two rules, both enforced in code rather than by
convention because "we're careful about it" is not something a security team
can audit:

1. **Egress is allowlisted.** A request to a host that policy does not permit
   raises before any bytes leave the process.
2. **Plaintext never reaches a remote provider.** Candidate secrets are sent as
   shape, entropy, rule name, masked value, and offsets. Local providers may
   receive plaintext only under a separate, explicit opt-in.
"""

from __future__ import annotations

import abc
import hashlib
import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

DEFAULT_TIMEOUT_S = 120

# Health probes are a UI interaction, not a scan: the settings page waits on
# every provider before it renders. A reachable endpoint answers in
# milliseconds, so the only thing a long timeout buys is a longer stare at a
# spinner when one is unreachable.
HEALTH_TIMEOUT_S = 5.0


class EgressBlocked(RuntimeError):  # noqa: N818 - names the action, not an error type
    """A call was attempted to a host the egress policy does not permit."""


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What a model can actually do, so the orchestrator can degrade rather
    than fail. Someone will point this at a 7B local model."""

    native_tool_calling: bool = False
    structured_output: bool = False
    context_window: int = 8192
    max_output_tokens: int = 4096
    vision: bool = False


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_s: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def as_json(self) -> dict[str, Any] | None:
        """Parse the response as JSON, tolerating the ways models wrap it.

        Small local models routinely emit fenced code blocks or a sentence
        before the object. Failing the whole triage pass over a stray ```json
        would be a poor trade.
        """
        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            parsed: dict[str, Any] = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                return None
            try:
                parsed = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        return parsed


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    healthy: bool
    provider: str
    model: str = ""
    detail: str = ""
    latency_s: float | None = None
    available_models: tuple[str, ...] = ()


class EgressPolicyGuard:
    """Enforces the allowlist at the point of the call.

    ``air_gapped`` is checked separately from the allowlist: an air-gapped
    deployment must fail on *configuration*, not on the first request, so an
    operator finds out at startup rather than mid-scan.
    """

    def __init__(
        self,
        *,
        allow_egress: bool,
        air_gapped: bool = False,
        allowed_hosts: tuple[str, ...] = (),
    ) -> None:
        self._allow_egress = allow_egress
        self._air_gapped = air_gapped
        self._allowed_hosts = allowed_hosts

    def check(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        if not host:
            raise EgressBlocked(f"could not determine host from {url!r}")

        if _is_local_host(host):
            # Loopback and private ranges are the local-provider case: an
            # Ollama box on the operator's own network is not egress in any
            # sense a security team cares about.
            return

        if self._air_gapped:
            raise EgressBlocked(
                f"air-gapped mode forbids contacting {host}; configure a local provider"
            )
        if not self._allow_egress:
            raise EgressBlocked(
                f"egress policy is 'deny' and {host} is not local; "
                "set BARE_EGRESS_POLICY=allow to permit cloud providers"
            )
        if self._allowed_hosts and host not in self._allowed_hosts:
            raise EgressBlocked(
                f"{host} is not in the egress allowlist {list(self._allowed_hosts)}"
            )

    def is_local(self, url: str) -> bool:
        return _is_local_host(urlparse(url).hostname or "")

    def check_remote_allowed(self, description: str) -> None:
        """Apply the policy when the destination host is not knowable.

        LiteLLM resolves some providers' endpoints internally and honours no
        `api_base` override for them, so there are calls whose URL this process
        never sees. Those still have to obey the policy, and the only safe
        reading of "I cannot tell you where this goes" under a deny policy is
        to refuse.
        """
        if self._air_gapped:
            raise EgressBlocked(
                f"air-gapped mode forbids {description}, whose endpoint is "
                "resolved by the provider library; configure a local provider"
            )
        if not self._allow_egress:
            raise EgressBlocked(
                f"egress policy is 'deny' and {description} is a hosted provider; "
                "set BARE_EGRESS_POLICY=allow to permit cloud providers"
            )
        if self._allowed_hosts:
            raise EgressBlocked(
                f"an egress allowlist is set, but {description} resolves its own "
                "endpoint, so it cannot be checked against it; use a provider "
                "with an explicit base URL instead"
            )


def _is_local_host(host: str) -> bool:
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


class LLMProvider(abc.ABC):
    """One model endpoint.

    Adapters are thin on purpose. Anything clever — retries, routing,
    redaction, auditing — belongs above this layer so it applies uniformly to
    every provider rather than being reimplemented six times.
    """

    kind: str = "abstract"

    def __init__(self, *, model: str, name: str, guard: EgressPolicyGuard) -> None:
        self.model = model
        self.name = name
        self._guard = guard

    @abc.abstractmethod
    def complete(
        self,
        messages: list[Message],
        *,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> Completion: ...

    @abc.abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abc.abstractmethod
    def health(self, *, timeout_s: float = HEALTH_TIMEOUT_S) -> ProviderHealth:
        """Probe reachability.

        Bounded because the settings page probes every provider on load, and an
        endpoint that is merely *gone* — a host that no longer answers, a LAN
        address off the network — black-holes the connection rather than
        refusing it. The wait is then the caller's timeout, per provider.
        """

    @property
    @abc.abstractmethod
    def is_local(self) -> bool:
        """Whether plaintext may be sent, subject to the operator's opt-in.

        Remote providers must return ``False`` unconditionally — this is the
        flag the redaction layer keys off.
        """

    def count_tokens(self, text: str) -> int:
        """Rough estimate. Used for budgeting, never for billing, so ~4 chars
        per token is close enough and avoids a tokeniser dependency per
        provider."""
        return max(1, len(text) // 4)

    @staticmethod
    def prompt_hash(messages: list[Message]) -> str:
        payload = "\x1f".join(f"{m.role}:{m.content}" for m in messages)
        return hashlib.sha256(payload.encode()).hexdigest()


def timed() -> float:
    return time.monotonic()
