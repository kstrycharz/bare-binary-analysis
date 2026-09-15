# Third-party notice — Ghidra

The `bare/ghidra` analyzer image contains **Ghidra**, which is not part of BARE
and is not a BARE product.

| | |
| --- | --- |
| Product | Ghidra |
| Vendor | National Security Agency, Research Directorate |
| Upstream | <https://github.com/NationalSecurityAgency/ghidra> |
| Version | 12.1.3 (`Ghidra_12.1.3_build`) |
| Archive | `ghidra_12.1.3_PUBLIC_20260817.zip` |
| SHA-256 | `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54` |
| License | Apache License 2.0 |

## How it is obtained

The image build downloads that exact archive from the NSA's own GitHub release
and verifies it against the SHA-256 published in the release notes. The build
fails if the digest does not match.

BARE therefore:

- **does not vendor Ghidra.** No Ghidra source or binary is committed to this
  repository. `git ls-files` contains a pinned URL and a digest, nothing more.
- **does not fork or patch Ghidra.** The extracted distribution is used as
  shipped. Nothing under `ghidra_*_PUBLIC/` is edited, replaced, or recompiled,
  and the image marks the whole tree read-only.
- **does not redistribute Ghidra.** The image is built on the operator's own
  machine from the upstream archive. BARE publishes no image containing it.
- **preserves upstream's licensing material.** `licenses/`, `LICENSE`, and
  `NOTICE` ship in the image exactly as upstream wrote them, at
  `/opt/ghidra/`. Nothing in this file supersedes them.

The only BARE-authored code inside the Ghidra distribution's reach is
`sandbox/ghidra_scripts/`, mounted read-only and passed to `analyzeHeadless`
via `-scriptPath`. Those are ordinary Ghidra scripts using the public
`GhidraScript` API — the documented extension point, not a modification.

## Why pinned rather than tracked

Ghidra is 569 MB and its analysis output changes between versions. A run
manifest that says "Ghidra" without a version cannot be reproduced, so the
version is pinned in `ghidra.lock.json`, recorded in every run manifest, and
bumped deliberately. See ADR-0034.

## Attribution in output

Ghidra produces no findings in BARE. It adds one thing to findings a
deterministic rule already made: the name of the function that references the
flagged string, shown as `in connect_broker()` beside the location. The run
manifest records Ghidra's version and image digest alongside every other
tool's, so it is always possible to say which Ghidra named a function.
