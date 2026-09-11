"""Process-wide configuration.

Everything is env-driven with safe defaults, and the defaults are the
*restrictive* ones: egress denied, dynamic analysis off, plaintext secret
retention off. An operator has to consciously loosen the posture; forgetting to
set a variable can never quietly open the trust boundary.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core import __version__

# Single source of truth; core/__init__.py is dependency-free by design.
BARE_VERSION = __version__


class EgressPolicy(StrEnum):
    DENY = "deny"
    ALLOW = "allow"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BARE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "development"
    log_level: str = "INFO"
    log_json: bool = True

    # --- storage ----------------------------------------------------------
    database_url: str = "postgresql+psycopg://bare:bare@postgres:5432/bare"
    redis_url: str = "redis://redis:6379/0"

    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key: str = "bare"
    s3_secret_key: str = "bare-secret-key"
    s3_bucket_artifacts: str = "bare-artifacts"
    s3_region: str = "us-east-1"

    # --- sandbox ----------------------------------------------------------
    sandbox_driver: str = "docker"
    run_root: Path = Path("/var/lib/bare/runs")
    """Directory holding per-run staging and results, as *this process* sees
    it. The only path an analyzer container may ever see."""

    run_root_host: str = ""
    """The same directory as the *Docker daemon* sees it, when the orchestrator
    is itself containerised. Empty means they are identical.

    Deliberately a ``str`` and not a ``Path``: on a Windows host reached from a
    Linux worker this holds something like ``C:\\bare\\runs``, which
    ``PosixPath.resolve()`` would mangle into a relative path under the
    container's cwd."""
    repo_root: Path = Path(".")
    """Used to resolve seccomp profile paths."""

    data_dir: Path = Path("/app/data")
    """Mutable state that must outlive a rebuild: the live LLM config and the
    provider key store. Everything under `repo_root` is baked into the image,
    so anything written there is discarded by the next `docker compose build` —
    which would silently throw away whatever the setup wizard configured."""

    analyzer_cpus: float = 4.0
    """CPU quota for an analyzer container, in whole cores.

    Rule matching is CPU-bound regex work over independent files, and the
    static analyzer parallelises across whatever quota it is given — it reads
    the cgroup limit rather than the host's core count, so this number is the
    real throughput knob. Measured on a 502-file .NET tree in the sandbox:
    23.4s at 1 core, 12.8s at 2, 5.4s at 8.

    Raising it does not widen the isolation boundary: the container still has
    no network, no capabilities, a read-only rootfs, and a wall-clock timeout
    with a watchdog behind it. What it bounds is how much CPU a hostile
    artifact can burn before that timeout fires, which is why it stays a
    modest default rather than "all of them"."""

    analyzer_memory_gb: float = 4.0
    """Memory ceiling for an analyzer container, in GiB.

    A ceiling rather than a target: the analyzer is deliberately bounded so a
    hostile artifact cannot exhaust the host, and an OOM is reported as a
    degraded stage rather than a crash (ADR-0008). Raise it for fleets that
    routinely scan large Electron or firmware trees — a 213 MB installer
    unpacks to ~69 000 files, which is the shape that pushes against it."""

    reaper_max_age_hours: int = 6
    reaper_interval_seconds: int = 300

    orphan_sweep_interval_seconds: int = 120
    orphan_queued_grace_seconds: int = 300
    """How long a run may sit queued before it is treated as orphaned.

    Long enough that a busy queue is never mistaken for a broken one, short
    enough that a lost run surfaces within a coffee break."""

    orphan_running_timeout_seconds: int = 3600
    """How long a run may stay `running` before it is failed.

    Must exceed every stage timeout with room to spare (unpack 900s + static
    1800s), so a legitimately slow scan of a large installer is never killed by
    the sweep."""

    orphan_max_requeue_attempts: int = 2
    """After this many requeues the problem is not transient, and the run is
    failed with a diagnosis rather than reappearing in the queue for ever."""

    # --- trust boundary ---------------------------------------------------
    auth_required: bool = True
    """Whether the API demands a token.

    True by default, which is the restrictive direction and the only defensible
    one: a release gate whose verdict anybody on the network can request, or
    whose findings anybody can read, is not a control.

    A fresh deployment is not bricked by this — the API mints a bootstrap admin
    token on first start and prints it once to the log (see
    `ensure_bootstrap_token`). Set to false only for a single-user local
    development stack, and never for anything reachable by another host."""

    egress_policy: EgressPolicy = EgressPolicy.DENY
    air_gapped: bool = False
    dynamic_analysis_enabled: bool = False
    retain_plaintext_secrets: bool = False

    require_attestation: bool = False
    """Whether uploads must carry an authorization attestation (§14).

    Off during prototyping so there is no upload friction. The schema, the
    audit records, and the report stamping all remain — flipping this back to
    ``true`` restores the gate with nothing to rebuild.

    Turn it on before anyone analyses an artifact they did not build."""

    default_attested_by: str = "prototype"
    default_attestation_reference: str = "Prototyping phase - attestation gate disabled"

    @field_validator("run_root", "repo_root", "data_dir")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        return value.expanduser().resolve()

    @property
    def llm_enabled(self) -> bool:
        """M3 wires this to config/llm.yaml. Until then the pipeline is
        deterministic-only, which is the CI default anyway (§2.5)."""
        return False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
