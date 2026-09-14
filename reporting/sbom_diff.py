"""What changed between two builds, as told by their SBOMs.

The exporter is deterministic precisely so two documents can be compared
(see ``reporting.cyclonedx``). This is the comparison: components added,
removed, changed version, or changed licence.

Components are matched by **identity, not by version**: the Package URL with
its version, qualifiers, and subpath stripped. Matching on the full purl would
report every upgrade as one removal plus one addition, which hides the single
most useful line — "zlib went from 1.2.11 to 1.2.13".

One artifact can legitimately bundle the same library twice at different
versions (an installer carrying two copies of zlib is ordinary). So each
identity maps to a *set* of versions, and a change is a change in that set.

Standard library only, and it reads CycloneDX JSON rather than the inventory
model, so it can diff two SBOMs attached to releases months apart — including
ones this deployment no longer holds the runs for.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

_NO_VERSION = ""


class SbomDiffError(ValueError):
    """A document that is not a CycloneDX SBOM this can read."""


@dataclass(frozen=True, slots=True)
class ComponentChange:
    key: str
    """Package identity: the purl without version, or ``name:<name>``."""
    name: str
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SbomDiff:
    before_label: str
    after_label: str
    added: tuple[ComponentChange, ...] = ()
    removed: tuple[ComponentChange, ...] = ()
    version_changed: tuple[ComponentChange, ...] = ()
    licence_changed: tuple[ComponentChange, ...] = ()
    unchanged: int = 0
    incomplete: tuple[str, ...] = field(default=())
    """Labels of documents built from a truncated walk. A component "removed"
    against one of those may simply not have been reached, and saying so is the
    difference between a diff and a false alarm."""

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.version_changed or self.licence_changed)


@dataclass(slots=True)
class _Group:
    name: str
    versions: set[str] = field(default_factory=set)
    licences: set[str] = field(default_factory=set)


def diff_sboms(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    before_label: str = "",
    after_label: str = "",
) -> SbomDiff:
    """Compare two CycloneDX documents."""
    old = _groups(before, "before")
    new = _groups(after, "after")

    added: list[ComponentChange] = []
    removed: list[ComponentChange] = []
    version_changed: list[ComponentChange] = []
    licence_changed: list[ComponentChange] = []
    unchanged = 0

    for key in sorted(old.keys() | new.keys()):
        a = old.get(key)
        b = new.get(key)
        if a is None and b is not None:
            added.append(ComponentChange(key, b.name, (), _sorted(b.versions)))
            continue
        if b is None and a is not None:
            removed.append(ComponentChange(key, a.name, _sorted(a.versions), ()))
            continue
        assert a is not None and b is not None
        same = True
        if a.versions != b.versions:
            version_changed.append(
                ComponentChange(key, b.name, _sorted(a.versions), _sorted(b.versions))
            )
            same = False
        if a.licences != b.licences:
            licence_changed.append(
                ComponentChange(key, b.name, _sorted(a.licences), _sorted(b.licences))
            )
            same = False
        unchanged += same

    labels = (
        (before_label or _label(before, "before"), before),
        (after_label or _label(after, "after"), after),
    )
    return SbomDiff(
        before_label=labels[0][0],
        after_label=labels[1][0],
        added=tuple(added),
        removed=tuple(removed),
        version_changed=tuple(version_changed),
        licence_changed=tuple(licence_changed),
        unchanged=unchanged,
        incomplete=tuple(label for label, doc in labels if not _inventory_complete(doc)),
    )


def identity(component: dict[str, Any]) -> tuple[str, str]:
    """``(key, version)`` for one component.

    The version comes from the component's own field when present, and from
    the purl otherwise; a purl-only document is still a valid SBOM.
    """
    name = str(component.get("name", "")).strip()
    version = str(component.get("version") or "").strip()
    purl = component.get("purl")
    if isinstance(purl, str) and purl.startswith("pkg:"):
        base = purl.split("#", 1)[0].split("?", 1)[0]
        # Only the last path segment can carry `@version`: a namespace `@` is
        # percent-encoded by the exporter (`pkg:npm/%40angular/core@12.3.1`),
        # but other generators write it raw, and splitting the whole string on
        # its last `@` would then cut `pkg:npm/@angular/core` in the wrong place.
        head, _, tail = base.rpartition("/")
        if "@" in tail:
            tail, _, purl_version = tail.partition("@")
            version = version or purl_version
        return (f"{head}/{tail}" if head else tail), version
    group = str(component.get("group", "")).strip()
    if not name:
        raise SbomDiffError("a component has neither a purl nor a name")
    return (f"name:{group}/{name}" if group else f"name:{name}"), version


def render_text(diff: SbomDiff) -> str:
    """For a terminal or a build log: ASCII only, sorted, one line per item."""
    lines = [
        f"SBOM diff: {diff.before_label} -> {diff.after_label}",
        (
            f"  {len(diff.added)} added, {len(diff.removed)} removed, "
            f"{len(diff.version_changed)} version changed, "
            f"{len(diff.licence_changed)} licence changed, {diff.unchanged} unchanged"
        ),
        "",
    ]
    sections: Iterable[tuple[str, str, tuple[ComponentChange, ...]]] = (
        ("ADDED", "+", diff.added),
        ("REMOVED", "-", diff.removed),
        ("VERSION CHANGED", "~", diff.version_changed),
        ("LICENCE CHANGED", "~", diff.licence_changed),
    )
    for title, mark, items in sections:
        if not items:
            continue
        lines.append(f"  {title} ({len(items)})")
        for item in items:
            lines.append(f"    {mark} {item.key}  {_describe(item, title)}")
        lines.append("")

    if not diff.has_changes:
        lines.append("  No component changes.")
        lines.append("")

    for label in diff.incomplete:
        lines.append(
            f"  warning: {label} was built from an incomplete inventory; a component "
            "shown as removed or added may only have been outside the walk."
        )
    return "\n".join(lines).rstrip("\n") + "\n"


def render_json(diff: SbomDiff) -> str:
    def items(changes: tuple[ComponentChange, ...]) -> list[dict[str, Any]]:
        return [
            {"key": c.key, "name": c.name, "before": list(c.before), "after": list(c.after)}
            for c in changes
        ]

    payload = {
        "before": diff.before_label,
        "after": diff.after_label,
        "added": items(diff.added),
        "removed": items(diff.removed),
        "version_changed": items(diff.version_changed),
        "licence_changed": items(diff.licence_changed),
        "unchanged": diff.unchanged,
        "incomplete": list(diff.incomplete),
        "has_changes": diff.has_changes,
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# -- internals --------------------------------------------------------------


def _groups(document: dict[str, Any], which: str) -> dict[str, _Group]:
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise SbomDiffError(f"the {which} document is not a CycloneDX SBOM")
    components = document.get("components", [])
    if components is None:
        components = []
    if not isinstance(components, list):
        raise SbomDiffError(f"the {which} document's 'components' is not a list")

    groups: dict[str, _Group] = {}
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise SbomDiffError(f"the {which} document's components[{index}] is not an object")
        key, version = identity(component)
        group = groups.setdefault(key, _Group(name=str(component.get("name", "")) or key))
        group.versions.add(version)
        group.licences.update(_licences(component))
    return groups


def _licences(component: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str):
            found.add(entry["expression"].strip())
        licence = entry.get("license")
        if isinstance(licence, dict):
            value = licence.get("id") or licence.get("name")
            if isinstance(value, str):
                found.add(value.strip())
    return found


def _metadata_component(document: dict[str, Any]) -> dict[str, Any]:
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        return dict(metadata["component"])
    return {}


def _property(document: dict[str, Any], name: str) -> str | None:
    for prop in _metadata_component(document).get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == name:
            return str(prop.get("value", ""))
    return None


def _inventory_complete(document: dict[str, Any]) -> bool:
    # Absent means a third-party SBOM that makes no claim either way; only an
    # explicit "false" is evidence of a truncated walk.
    return _property(document, "bare:inventory_complete") != "false"


def _label(document: dict[str, Any], fallback: str) -> str:
    name = str(_metadata_component(document).get("name", "")).strip()
    run = _property(document, "bare:run")
    if name and run:
        return f"{name} (run {run})"
    return name or (f"run {run}" if run else fallback)


def _sorted(values: set[str]) -> tuple[str, ...]:
    return tuple(sorted(values))


def _describe(item: ComponentChange, section: str) -> str:
    def show(values: tuple[str, ...]) -> str:
        return ", ".join(v if v != _NO_VERSION else "(unversioned)" for v in values) or "(none)"

    if section == "ADDED":
        return show(item.after)
    if section == "REMOVED":
        return show(item.before)
    return f"{show(item.before)} -> {show(item.after)}"
