"""Does Ghidra, inside the real sandbox, name the function that reads a string?

The unit suite drives the analyzer with a fake analyzeHeadless. This runs the
real image through the real driver — seccomp allowlist, read-only rootfs, no
network, uid 10001, the default ulimits — over a binary compiled on the spot,
and asserts the one thing S4 exists to establish: the flagged string's file
offset resolves to the function that uses it.

Requires Docker, ``bare/ghidra`` (``make image-ghidra``; the tag follows
``BARE_ANALYZER_TAG``), and a C compiler on PATH — gcc, or MinGW's gcc on
Windows. Skipped otherwise. Slow: a JVM start plus auto-analysis, ~15 s.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from core.analyzers.ghidra_result import GhidraResult
from core.sandbox import BindMount, DockerDriver, MountMode, SandboxSpec, SandboxStatus
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR

pytestmark = [pytest.mark.integration, pytest.mark.slow]

GHIDRA_IMAGE = analyzer_image("ghidra")

# The provably-invalid documentation key: a real shape, never a real credential.
NEEDLE = b"AKIAIOSFODNN7EXAMPLE"

PROBE_SOURCE = """
#include <stdio.h>
#include <string.h>
static const char *BROKER_KEY = "AKIAIOSFODNN7EXAMPLE";
__attribute__((noinline)) int connect_broker(const char *host) {
    printf("connecting to %s with %s\\n", host, BROKER_KEY);
    return (int)strlen(BROKER_KEY);
}
int main(void) { return connect_broker("mqtt.example.invalid") > 0 ? 0 : 1; }
"""


@pytest.fixture(scope="module")
def docker_client() -> Any:
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Docker is not available: {exc}")
    try:
        client.images.get(GHIDRA_IMAGE)
    except Exception:  # pragma: no cover - environment dependent
        pytest.skip(f"{GHIDRA_IMAGE} is not built; run `make image-ghidra`")
    return client


@pytest.fixture(scope="module")
def compiler() -> str:
    found = shutil.which("gcc") or shutil.which("cc")
    if found is None:  # pragma: no cover - environment dependent
        pytest.skip("no C compiler on PATH to build the probe binary")
    return found


def _stage(tmp_path: Path, compiler: str, *, strip: bool) -> tuple[Path, Path, Path, int]:
    run_root = tmp_path / "runs"
    inputs = run_root / "run-ghidra" / "in"
    results = run_root / "run-ghidra" / "out"
    binaries = inputs / "binaries"
    binaries.mkdir(parents=True)
    results.mkdir(parents=True)

    source = tmp_path / "probe.c"
    source.write_text(PROBE_SOURCE, encoding="utf-8")
    binary = binaries / "probe"
    argv = [compiler, "-O1", "-o", str(binary), str(source)]
    if strip:
        argv.insert(2, "-s")
    subprocess.run(argv, check=True, capture_output=True)
    if not binary.exists() and binary.with_suffix(".exe").exists():
        binary.with_suffix(".exe").rename(binary)  # MinGW appends .exe

    offset = binary.read_bytes().find(NEEDLE)
    assert offset > 0
    (inputs / "targets.json").write_text(
        json.dumps({"binaries": [{"path": "probe", "offsets": [offset]}]}), encoding="utf-8"
    )
    if os.name != "nt":
        results.chmod(0o777)
    return run_root, inputs, results, offset


@pytest.mark.parametrize("strip", [False, True], ids=["symbols", "stripped"])
def test_the_flagged_string_resolves_to_the_function_that_uses_it(
    tmp_path: Path, docker_client: Any, compiler: str, strip: bool
) -> None:
    run_root, inputs, results, offset = _stage(tmp_path, compiler, strip=strip)
    driver = DockerDriver(run_root=run_root, repo_root=Path.cwd(), client=docker_client)

    result = driver.run(
        SandboxSpec(
            image=GHIDRA_IMAGE,
            run_id="run-ghidra",
            analyzer="ghidra",
            command=("--total-timeout", "600", "--per-binary-timeout", "600"),
            timeout_s=900,
            mounts=(
                BindMount(str(inputs), INPUT_DIR, MountMode.READ_ONLY),
                BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
            ),
        )
    )

    assert result.status is SandboxStatus.COMPLETED, result.error or result.stderr[-2000:]
    assert result.exit_code == 0, result.stdout[-2000:]

    parsed = GhidraResult.from_json(
        json.loads((results / "result.json").read_text(encoding="utf-8"))
    )
    (binary,) = parsed.binaries
    assert binary.status == "analyzed", binary.reason
    assert parsed.ghidra_version != "unknown"

    function = parsed.xref_functions().get(("probe", offset))
    if strip:
        # No symbol table: Ghidra still finds the function, and names it by
        # its entry point. Found is the claim; the name is Ghidra's to choose.
        assert function is not None and function.startswith("FUN_")
    else:
        assert function == "connect_broker"
