# Reporting and binary composition analysis

Two related gaps, planned together because the second is what makes the first
worth reading: BARE can say *what secrets an artifact leaks* but not
*what the artifact is made of*. A release record that answers only the first
question is half a document.

Grounded throughout in a real artifact — `NVIDIA-AI-Workbench-Setup.exe`,
213 MB, scanned by this tool on 2026-08-25.

---

## 1. What the NVIDIA scan actually showed

Worth stating plainly, because it sets the scope.

**Unpacking works, and works deep.** The installer opens three levels down:

```
NVIDIA-AI-Workbench-Setup.exe   (NSIS, 213 MB)
└─ $PLUGINSDIR/app-64.7z        (212 MB)
   ├─ NVIDIA AI Workbench.exe   (227 MB, PE)
   ├─ resources/app.asar        (377 MB, Electron archive)
   ├─ resources/bin/wb-svc      (41 MB, ELF)
   └─ LICENSES.chromium.html    (20 MB)
```

**Two real defects came out of it**, both now fixed:

* The 20 000-file extraction budget was hit six seconds in, so `app.asar` — the
  application's own code — was never opened. The budget now scales with input
  size (213 MB → 121 800 files).
* That truncation was recorded as a `completed` stage, so the gate never saw
  it and returned **PASS** on an artifact whose code had not been examined.
  Truncation is now its own degraded status and the gate returns
  **INCONCLUSIVE** (ADR-0018).

**And one gap that is not a defect but an absence.** Inside that `app.asar`,
in the truncated slice alone:

| Evidence present | Count | What BARE reports today |
| --- | --- | --- |
| `package.json` manifests | 1 570 | nothing |
| License files | 66 | nothing |
| Declared components (`name@version`) | 1 570+ | nothing |

The tool walked past 1 570 declarations of *exactly which version of exactly
which library* this product ships, and reported none of them. That is the Black
Duck Binary Analysis capability, and it is missing rather than broken.

---

## 2. Where BARE already is

The foundations are unusually good for this, and that is the argument for
building on them rather than bolting on a scanner:

| Have | Why it matters here |
| --- | --- |
| Recursive unpacking with provenance (`a → b → c`) | Components must be attributed to *where in the artifact* they were found |
| Content-derived, stable finding IDs (ADR-0010) | The same mechanism answers "which components are new since last release" |
| A deterministic spine, LLM strictly advisory (§2.5) | A CVE match must never be a model's opinion |
| The release gate with baseline and waivers | Component risk needs the same "fail on what this build introduced" logic |
| Air-gap capability, egress denied by default | The hard constraint that shapes every design choice below |
| SARIF export | The same projection extends to CycloneDX |

---

## 3. Reporting (M4)

Four outputs, in the order they earn their keep.

### 3.1 CycloneDX SBOM — do this first

Not because it is easiest, but because it is the artifact everyone else
consumes, and because §2's evidence means we can populate it honestly today.

* One `component` per identified component, with a **PURL**
  (`pkg:npm/@babel/parser@7.26.2`) and the unpack path it was found at.
* `evidence.identity` carrying *how* we know — a declared manifest is a
  different confidence from a fuzzy binary match, and CycloneDX has a field for
  saying so. Guessing silently is how SBOMs lose their audience.
* Emitted from the same run manifest that already pins the rule-pack hash, so
  an SBOM is reproducible from a run id.

### 3.2 PDF release record

The document a release manager signs and an auditor reads a year later.
Deterministic layout — same run, byte-identical PDF — because a report that
differs between renderings cannot be an audit record.

Contents: the gate verdict and the policy that produced it, the attestation,
the artifact tree with hashes, findings by severity with masked values only,
the component inventory, and the methodology appendix (analyzer versions, image
digests, tool versions) that the run manifest already collects.

### 3.3 HTML report

The same content, self-contained and offline — the thing that gets emailed.
Shares the renderer with the PDF; no second source of truth.

### 3.4 What already exists

SARIF 2.1.0 ships today and feeds code scanning. It stays the developer-facing
output; none of the above replaces it.

---

## 4. Binary composition analysis

The Black Duck BA capability, in three layers of increasing difficulty. Each is
independently useful, which is the point of the ordering — layer 1 alone
produces a real SBOM.

### Layer 1 — Declared components (weeks, high confidence)

Read what the artifact says about itself. Every ecosystem leaves a manifest:

| Source | Yields | Present in the NVIDIA artifact |
| --- | --- | --- |
| `package.json` | name, version, license, dependencies | **1 570** |
| PE version resources | product, vendor, version | yes, every DLL |
| Go build info (`buildinfo`) | module paths and versions | `wb-svc`, `nvwb-cli` |
| .NET assembly metadata | assembly name and version | yes |
| ELF `DT_SONAME` / `.comment` | library name, compiler | yes |
| `.nuspec`, `METADATA`, `Cargo.lock` | name, version | ecosystem-dependent |

High confidence, no guessing, no external data. This is the layer that turns
1 570 ignored files into an inventory.

### Layer 2 — Vulnerability matching (the air-gap problem)

Once components carry PURLs, CVEs are a join. The difficulty is not the join —
it is that **this product runs air-gapped and denies egress by default**, so a
live API call to OSV or NVD is not available and never will be.

The design that follows from that constraint:

* A **mirrored, versioned advisory database** shipped as a signed bundle —
  the same shape as `make airgap-bundle`, which already exists as a stub.
* Every report states **the advisory snapshot date**. "No known CVEs" is
  meaningless without it, and a scanner that implies currency it does not have
  is worse than one that admits staleness.
* Matching stays deterministic: PURL and version range in, CVE out. No model
  anywhere near it (§2.5).
* Version-range matching is the part that is genuinely hard to get right —
  `>=1.2.0 <1.4.7` across ecosystems with different ordering rules. Use an
  existing, tested implementation rather than writing one.

### Layer 3 — Undeclared components (hard, and honest about it)

A statically-linked binary carries no manifest. Identifying zlib inside a
57 MB Go binary means fingerprinting: function-level hashes, distinctive string
constants, embedded version banners.

This is where Black Duck's value actually sits, and where a corpus is the
product — building one is a sustained effort, not a sprint. Sequenced last, and
deliberately scoped to **high-confidence signals only** at first: embedded
version banners (`zlib 1.3.1`, `OpenSSL 3.0.13`) are cheap, common, and
verifiable. Fuzzy matching without a curated corpus produces confident nonsense,
which in this product would be worse than silence.

### License compliance

Falls out of layer 1 and is arguably the fastest win after the SBOM: 66 license
files sat in the truncated slice alone. SPDX identification from license text is
a solved problem with existing datasets, and "this product ships GPL code" is a
question a release manager is asked more often than they are asked about CVEs.

---

## 5. How this reaches the gate

Composition findings must flow through the *existing* policy engine, not a
parallel one. The concepts already fit:

```yaml
block:
  severity_at_or_above: high
  components:
    max_cvss: 8.0              # a component CVE at or above this blocks
    licenses: [AGPL-3.0, SSPL-1.0]   # licences that block a commercial release
    advisory_max_age_days: 30  # refuse to gate on a stale advisory snapshot
```

Three properties carry over unchanged, and they are the reason to build it here
rather than buy it:

* **Baseline** — a CVE inherited from last release does not fail this build;
  a newly-introduced vulnerable dependency does (ADR-0016).
* **Waivers** — "we accept CVE-2024-x until the vendor ships 2.5" is exactly
  the expiring, owned, reviewed waiver the gate already models.
* **INCONCLUSIVE** — a stale advisory snapshot, or a truncated extraction,
  cannot support a PASS (ADR-0018). The bug found in §1 is the same principle.

---

## 6. Sequence

| Order | Work | Why here |
| --- | --- | --- |
| 1 | Layer 1: manifest-based component inventory | Highest value per effort; needs no external data |
| 2 | CycloneDX export | Makes layer 1 consumable by everything else |
| 3 | License identification | Falls out of layer 1; answers a question that gets asked |
| 4 | PDF / HTML release record | Now has something worth printing |
| 5 | Layer 2: mirrored advisories, CVE matching, gate policy | The air-gap bundle is the real work |
| 6 | Layer 3: binary fingerprinting | Sustained corpus effort; scope to version banners first |

Steps 1–3 are the ones that change what the product *is*. Everything after is
depth on an inventory that already exists.

---

## 7. What this is not

* **Not a replacement for source-code SCA.** BARE looks at what shipped.
  A dependency scanned in CI and a dependency present in the binary are
  different facts, and the gap between them is often the interesting finding.
* **Not a licence-compliance legal opinion.** It reports what it identified and
  how confidently.
* **Not model-driven.** A CVE match is deterministic or it is not a match. The
  LLM layer may explain and prioritise, never assert (§2.5).
