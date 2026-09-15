"""Analyzer image names, in one place.

The tag was hard-coded to ``dev`` in eight files — the Makefile, its PowerShell
twin, the scan pipeline, the orchestrator, the CLI, CI, and two test modules.
That is fine while the only deployment is a developer's laptop and wrong the
moment anyone ships a versioned build, because there is no way to say "run
0.1.0" without editing source.

Resolution order, most specific first:

1. ``BARE_<NAME>_IMAGE`` — a complete image reference for one analyzer,
   e.g. ``BARE_STATIC_IMAGE=registry.internal/bare/static@sha256:...``.
   This predates the tag setting and keeps working; it is also the only way to
   pin a digest or move one analyzer to a different registry.
2. ``BARE_ANALYZER_TAG`` — the tag applied to every analyzer repository.
   The common case: ``latest``, a release version, or a git sha.
3. ``dev`` — unchanged from before, so existing workflows need no flags.

Read from the environment at call time rather than captured at import. The
constants this replaces were evaluated once when the module first loaded, which
meant a test (or a worker that set the variable after start-up) could not
change them.
"""

from __future__ import annotations

import os

DEFAULT_TAG = "dev"
REGISTRY_NAMESPACE = "bare"

# The analyzers this project builds. `make images` and the image-name helper
# read the same list so a new analyzer cannot be added to one and forgotten in
# the other.
ANALYZERS = ("hello", "static", "unpack", "ghidra")


def analyzer_tag() -> str:
    """The tag every analyzer image is built and run with."""
    # An exported-but-empty variable is the usual shape of a broken deployment
    # script; treating it as a tag would produce `bare/static:` and a
    # confusing daemon error rather than the default.
    return os.environ.get("BARE_ANALYZER_TAG", "").strip() or DEFAULT_TAG


def analyzer_image(name: str) -> str:
    """The full image reference for one analyzer, e.g. ``bare/static:dev``."""
    override = os.environ.get(f"BARE_{name.upper()}_IMAGE", "").strip()
    if override:
        return override
    return f"{REGISTRY_NAMESPACE}/{name}:{analyzer_tag()}"
