"""The providers the setup wizard offers, and what each one needs.

Data, not code. Everything except local Ollama goes through LiteLLM, so adding
a vendor is adding a row — the `model` string carries the provider prefix
LiteLLM routes on, and no adapter is involved.

That is also the limit of what this file is for. LiteLLM reaches well over a
hundred providers; these are the ones worth putting in front of someone during
setup, and the wizard lets an operator type any LiteLLM model string for the
rest.

Model defaults are chosen for the `triage` role, which runs thousands of times
per scan: small, fast, cheap, non-reasoning. A reasoning model here is the
single most common way to make BARE look broken — it spends its whole
token budget deliberating and returns nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    id: str
    label: str
    kind: str
    """The vendor name written into config/llm.yaml. Selects no code path —
    LiteLLM routes on the model string's prefix — but it is what an operator
    expects to read back. `ollama` is the exception and does select an
    adapter."""
    base_url: str
    default_model: str
    requires_key: bool
    is_local: bool
    """Whether this runs on the operator's own hardware. Decides whether the
    egress policy permits it at all, and whether plaintext could ever be sent
    under an explicit opt-in."""
    summary: str
    key_hint: str = ""
    key_url: str = ""
    suggested_models: tuple[str, ...] = field(default_factory=tuple)
    needs_base_url: bool = False
    """True when there is no sensible default and the operator must supply one."""


CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="ollama",
        label="Ollama (local)",
        kind="ollama",
        base_url="http://localhost:11434",
        default_model="qwen2.5-coder:7b-instruct-q4_K_M",
        requires_key=False,
        is_local=True,
        summary=(
            "Runs on your own hardware. Nothing leaves your network, which is the "
            "only option that keeps an air-gapped deployment air-gapped."
        ),
        suggested_models=(
            "qwen2.5-coder:7b-instruct-q4_K_M",
            "qwen2.5-coder:14b-instruct-q4_K_M",
            "llama3.2:3b",
        ),
    ),
    CatalogEntry(
        id="vllm",
        label="vLLM / LM Studio (local)",
        kind="vllm",
        base_url="http://localhost:8000/v1",
        default_model="hosted_vllm/",
        requires_key=False,
        is_local=True,
        summary=(
            "Any server that speaks the OpenAI chat API on your own network. "
            "Faster than Ollama at volume, and the same privacy position."
        ),
        needs_base_url=True,
    ),
    CatalogEntry(
        id="openai",
        label="OpenAI",
        kind="openai",
        base_url="",
        default_model="gpt-4o-mini",
        requires_key=True,
        is_local=False,
        summary="Hosted. Fast and inexpensive at triage volume.",
        key_hint="Starts with sk-",
        key_url="https://platform.openai.com/api-keys",
        suggested_models=("gpt-4o-mini", "gpt-4o", "o4-mini"),
    ),
    CatalogEntry(
        id="anthropic",
        label="Anthropic",
        kind="anthropic",
        base_url="",
        default_model="anthropic/claude-haiku-4-5-20251001",
        requires_key=True,
        is_local=False,
        summary="Hosted. Haiku for triage volume, Sonnet for explanations.",
        key_hint="Starts with sk-ant-",
        key_url="https://console.anthropic.com/settings/keys",
        suggested_models=(
            "anthropic/claude-haiku-4-5-20251001",
            "anthropic/claude-sonnet-4-5-20250929",
        ),
    ),
    CatalogEntry(
        id="gemini",
        label="Google Gemini",
        kind="gemini",
        base_url="",
        default_model="gemini/gemini-2.0-flash",
        requires_key=True,
        is_local=False,
        summary="Hosted. Flash models are well suited to triage volume.",
        key_url="https://aistudio.google.com/apikey",
        suggested_models=("gemini/gemini-2.0-flash", "gemini/gemini-2.5-flash"),
    ),
    CatalogEntry(
        id="azure",
        label="Azure OpenAI",
        kind="azure",
        base_url="",
        default_model="azure/<your-deployment-name>",
        requires_key=True,
        is_local=False,
        summary=(
            "Hosted in your own Azure tenant. The model is your deployment name; "
            "the endpoint is your resource URL."
        ),
        key_hint="Your Azure OpenAI key",
        needs_base_url=True,
    ),
    CatalogEntry(
        id="bedrock",
        label="AWS Bedrock",
        kind="bedrock",
        base_url="",
        default_model="bedrock/anthropic.claude-3-5-haiku-20241022-v1:0",
        requires_key=True,
        is_local=False,
        summary=(
            "Hosted in your own AWS account. Authenticates with AWS credentials "
            "rather than a bearer token — set AWS_ACCESS_KEY_ID and friends in "
            "the environment."
        ),
        key_hint="AWS secret access key",
    ),
    CatalogEntry(
        id="vertex",
        label="Google Vertex AI",
        kind="vertex_ai",
        base_url="",
        default_model="vertex_ai/gemini-2.0-flash",
        requires_key=True,
        is_local=False,
        summary="Hosted in your own GCP project, with Google Cloud credentials.",
    ),
    CatalogEntry(
        id="groq",
        label="Groq",
        kind="groq",
        base_url="",
        default_model="groq/llama-3.3-70b-versatile",
        requires_key=True,
        is_local=False,
        summary="Hosted. Very low latency per call, which suits triage volume.",
        key_hint="Starts with gsk_",
        key_url="https://console.groq.com/keys",
    ),
    CatalogEntry(
        id="mistral",
        label="Mistral",
        kind="mistral",
        base_url="",
        default_model="mistral/mistral-small-latest",
        requires_key=True,
        is_local=False,
        summary="Hosted, European. Small models are cheap at triage volume.",
        key_url="https://console.mistral.ai/api-keys",
    ),
    CatalogEntry(
        id="deepseek",
        label="DeepSeek",
        kind="deepseek",
        base_url="",
        default_model="deepseek/deepseek-chat",
        requires_key=True,
        is_local=False,
        summary="Hosted. Inexpensive; the reasoner variant suits explanations.",
        key_url="https://platform.deepseek.com/api_keys",
    ),
    CatalogEntry(
        id="xai",
        label="xAI Grok",
        kind="xai",
        base_url="",
        default_model="xai/grok-3-mini",
        requires_key=True,
        is_local=False,
        summary="Hosted.",
        key_url="https://console.x.ai",
    ),
    CatalogEntry(
        id="together",
        label="Together AI",
        kind="together_ai",
        base_url="",
        default_model="together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo",
        requires_key=True,
        is_local=False,
        summary="Hosted gateway to many open-weight models.",
        key_url="https://api.together.ai/settings/api-keys",
    ),
    CatalogEntry(
        id="fireworks",
        label="Fireworks AI",
        kind="fireworks_ai",
        base_url="",
        default_model="fireworks_ai/accounts/fireworks/models/llama-v3p3-70b-instruct",
        requires_key=True,
        is_local=False,
        summary="Hosted gateway to many open-weight models.",
        key_url="https://fireworks.ai/account/api-keys",
    ),
    CatalogEntry(
        id="openrouter",
        label="OpenRouter",
        kind="openrouter",
        base_url="",
        default_model="openrouter/openai/gpt-4o-mini",
        requires_key=True,
        is_local=False,
        summary="Hosted gateway to many vendors behind one key.",
        key_hint="Starts with sk-or-",
        key_url="https://openrouter.ai/keys",
    ),
    CatalogEntry(
        id="litellm-proxy",
        label="LiteLLM Proxy",
        kind="litellm_proxy",
        base_url="",
        default_model="litellm_proxy/<model>",
        requires_key=True,
        is_local=False,
        summary=(
            "Your own LiteLLM gateway, if you already run one. Point this at it "
            "and it governs which vendors are reachable."
        ),
        needs_base_url=True,
    ),
    CatalogEntry(
        id="custom",
        label="Other (any LiteLLM model)",
        kind="litellm",
        base_url="",
        default_model="",
        requires_key=False,
        is_local=False,
        summary=(
            "Anything else LiteLLM supports. Give the model in its "
            "provider/model form, and a base URL if it needs one."
        ),
    ),
)

BY_ID: dict[str, CatalogEntry] = {entry.id: entry for entry in CATALOG}
