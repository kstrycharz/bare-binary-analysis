"""Identifying components from what an artifact declares about itself.

Layer 1 of composition analysis: read the manifests. Every ecosystem leaves
one, and a declaration is worth far more than a guess — `package.json` says
`@babel/parser@7.26.2` outright, and no fingerprint corpus is needed to believe
it.

This is deliberately the *high-confidence* layer. Fuzzy matching against a
signature corpus (layer 3 in docs/ROADMAP-COMPOSITION.md) finds statically
linked libraries that declare nothing, and it is a sustained corpus effort that
produces confident nonsense without one. Declarations first.

Measured on a real artifact: the NVIDIA AI Workbench installer ships 1 570
`package.json` files inside its Electron archive. Before this module, every one
of them was walked past.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.composition.model import Component, ComponentInventory, Confidence, Ecosystem

# A manifest is small. Anything larger is not one, and reading it would only
# slow the walk down.
MAX_MANIFEST_BYTES = 512 * 1024

# Bounded like every other sweep here: a pathological tree must not turn the
# inventory into an unbounded allocation.
MAX_COMPONENTS = 50_000


def _clean(value: object) -> str:
    text = str(value or "").strip()
    return text if text and text.lower() not in ("unknown", "none", "null") else ""


# npm's `license` field is frequently a pointer to a file rather than a licence:
# `SEE LICENSE IN ./LICENSE.md`, or just `./LICENSE.md`. Passing those through as
# an SPDX expression puts a string in the SBOM that no downstream tool can
# evaluate, and a licence field that cannot be evaluated is worse than an absent
# one — it reads as an answer. Observed on 4 of 1 003 components in a real
# Electron installer.
_NOT_AN_EXPRESSION = re.compile(r"^(see\s|\.{0,2}/)|\.(md|txt|html)$", re.I)


def _as_spdx_expression(text: str) -> str:
    """Keep only what could be an SPDX expression."""
    return "" if _NOT_AN_EXPRESSION.search(text) else text


def _licence_from(document: dict[str, object]) -> str:
    """npm allows a string or an object, and older packages an array."""
    raw = document.get("license") or document.get("licence")
    if isinstance(raw, str):
        return _as_spdx_expression(_clean(raw))
    if isinstance(raw, dict):
        return _as_spdx_expression(_clean(raw.get("type")))
    if isinstance(raw, list) and raw:
        first = raw[0]
        if isinstance(first, dict):
            return _as_spdx_expression(_clean(first.get("type")))
        return _as_spdx_expression(_clean(first))
    return ""


def from_package_json(path: Path, path_in_tree: str) -> Component | None:
    """npm. The densest source of components in any Electron artifact."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict):
        return None

    name = _clean(document.get("name"))
    version = _clean(document.get("version"))
    if not name or not version:
        # A package.json without both is a project scaffold or a config file,
        # not a shipped component.
        return None

    return Component(
        name=name,
        version=version,
        ecosystem=Ecosystem.NPM,
        confidence=Confidence.DECLARED,
        path_in_tree=path_in_tree,
        licence=_licence_from(document),
        evidence="package.json",
    )


def from_nuspec(path: Path, path_in_tree: str) -> Component | None:
    """NuGet. Parsed with a regex rather than an XML parser on purpose: this
    runs over hostile input, and `xml.etree` on an untrusted document is an
    entity-expansion problem waiting to happen."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    name = re.search(r"<id>\s*([^<]{1,200})</id>", text, re.I)
    version = re.search(r"<version>\s*([^<]{1,80})</version>", text, re.I)
    if not name or not version:
        return None

    licence = re.search(r"<license[^>]*>\s*([^<]{1,120})</license>", text, re.I)
    return Component(
        name=_clean(name.group(1)),
        version=_clean(version.group(1)),
        ecosystem=Ecosystem.NUGET,
        confidence=Confidence.DECLARED,
        path_in_tree=path_in_tree,
        licence=_as_spdx_expression(_clean(licence.group(1))) if licence else "",
        evidence=".nuspec",
    )


def from_python_metadata(path: Path, path_in_tree: str) -> Component | None:
    """PyPI. `METADATA` inside a `.dist-info`, as PEP 566 defines it."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    name = re.search(r"^Name:\s*(.+)$", text, re.M)
    version = re.search(r"^Version:\s*(.+)$", text, re.M)
    if not name or not version:
        return None

    licence = re.search(r"^License:\s*(.+)$", text, re.M)
    return Component(
        name=_clean(name.group(1)),
        version=_clean(version.group(1)),
        ecosystem=Ecosystem.PYPI,
        confidence=Confidence.DECLARED,
        path_in_tree=path_in_tree,
        licence=_as_spdx_expression(_clean(licence.group(1))) if licence else "",
        evidence="dist-info METADATA",
    )


# Go stamps its module graph into the binary. `go version -m` reads exactly
# this; the format is stable and the marker is distinctive enough to find
# without parsing the ELF/PE structure.
_GO_BUILDINFO = re.compile(
    rb"\xff Go buildinf:|(?:^|\x00)(?:dep|mod)\t([\w./+~-]{3,180})\t(v[\w.+~-]{1,60})\t"
)
_GO_DEP_LINE = re.compile(rb"(?:dep|mod)\t([\w./+~-]{3,180})\t(v[\w.+~-]{1,60})")


def from_go_binary(
    path: Path, path_in_tree: str, *, max_bytes: int = 64 * 1024 * 1024
) -> list[Component]:
    """Go module dependencies, read from the embedded build info.

    Go binaries are statically linked, so without this a 40 MB service reports
    as one opaque file — which is precisely the case binary composition
    analysis exists for.
    """
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return []

    if b"Go buildinf:" not in data[:max_bytes]:
        return []

    seen: set[tuple[str, str]] = set()
    components: list[Component] = []
    for match in _GO_DEP_LINE.finditer(data):
        name = match.group(1).decode("utf-8", "replace")
        version = match.group(2).decode("utf-8", "replace")
        if (name, version) in seen or "." not in name:
            continue
        seen.add((name, version))
        components.append(
            Component(
                name=name,
                version=version,
                ecosystem=Ecosystem.GOLANG,
                confidence=Confidence.DECLARED,
                path_in_tree=path_in_tree,
                evidence="Go buildinfo",
            )
        )
    return components


# Recognised by exact filename; extensions alone are too broad.
_BY_NAME = {
    "package.json": from_package_json,
    "metadata": from_python_metadata,
}


def detect_in_file(path: Path, path_in_tree: str) -> list[Component]:
    """Every component this one file declares."""
    name = path.name.lower()

    if name in _BY_NAME:
        # METADATA is only a Python manifest inside a .dist-info directory;
        # elsewhere it is any file called metadata.
        if name == "metadata" and ".dist-info" not in path_in_tree.lower():
            return []
        found = _BY_NAME[name](path, path_in_tree)
        return [found] if found else []

    if name.endswith(".nuspec"):
        found = from_nuspec(path, path_in_tree)
        return [found] if found else []

    # Go binaries are found by content, not by name — they have no extension
    # on Linux and an ordinary .exe on Windows.
    try:
        if path.stat().st_size > 1_000_000:
            with path.open("rb") as handle:
                head = handle.read(4)
            if head.startswith((b"\x7fELF", b"MZ")):
                return from_go_binary(path, path_in_tree)
    except OSError:
        return []

    return []


def inventory(
    files: list[tuple[Path, str]], *, max_components: int = MAX_COMPONENTS
) -> ComponentInventory:
    """Walk a staged tree and return its bill of materials.

    ``files`` is ``(on-disk path, path_in_tree)``. Deduplicated on
    (ecosystem, name, version) and sorted, so the inventory is byte-identical
    across runs of the same artifact — an SBOM that reorders between builds
    makes every diff useless.
    """
    seen: dict[tuple[str, str, str], Component] = {}
    truncated = False

    for path, path_in_tree in files:
        if len(seen) >= max_components:
            truncated = True
            break
        for component in detect_in_file(path, path_in_tree):
            seen.setdefault(component.key, component)

    ordered = sorted(seen.values(), key=lambda c: (c.ecosystem.value, c.name.lower(), c.version))
    return ComponentInventory(
        components=tuple(ordered),
        files_examined=len(files),
        truncated=truncated,
    )
