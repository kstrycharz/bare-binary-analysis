# BARE

*Binary Analysis & Reverse Engineering*

**A self-hosted platform that reverse engineers the binaries you are about to
ship, and reports what they give away.**

Point it at an installer, executable, DLL, firmware image, or update bundle.
BARE unpacks the artifact recursively inside a disposable Docker sandbox with
no network, reverse engineers what comes out, and reports the credentials,
internal hostnames, build paths, and third-party components compiled into the
thing your customer actually receives. Run it as a dashboard, or as a CI stage
gate that fails the build with a meaningful exit code.

Everyone scans their source code. Almost nobody looks at the binary that comes
out the other end — and the build pipeline is where the leak happens. CI
environment variables get baked into strings tables. Debug builds ship PDB
paths exposing internal directory trees and developer usernames. An installer
bundles a `config.default.json` with a real staging token in it.

**Every finding is produced by a deterministic rule.** The optional LLM layer
triages, explains, and investigates on top of that spine — it never invents a
finding, and the entire pipeline runs without it. Self-hosted and air-gap
capable: your artifacts never leave your network.

## Under the hood

| Stage | What does the work |
| --- | --- |
| **Isolation** | Docker, one disposable container per analyzer — seccomp allowlist, no network, no DNS, read-only rootfs, all capabilities dropped, non-root, tmpfs scratch, plus a watchdog and a reaper |
| **Unpacking** | `p7zip` (7z, ZIP, CAB, MSI, ISO, NSIS, InnoSetup), `squashfs-tools`, `cabextract` — recursive, magic-byte container detection, hard cumulative budgets as the zip-bomb defence |
| **String extraction** | Printable-run extractor over ASCII and UTF-16LE, parallelised across the container's CPU quota |
| **Detection** | YAML rule packs — id, severity, CWE, remediation, and required pass/fail fixtures — matched with Shannon-entropy floors and per-rule exclusion lists |
| **Recon sweep** | A deliberately over-broad inventory pass (every URI scheme, UNC path, hostname, UPN) to surface what nobody wrote a rule for |
| **Composition** | Components read from embedded `package.json`, `.dist-info/METADATA`, `.nuspec`, and Go build info → Package URL → CycloneDX SBOM |
| **Orchestration** | FastAPI, Celery on Redis, PostgreSQL, MinIO, Next.js dashboard |
| **Reporting** | SARIF 2.1.0, CycloneDX 1.5, PDF release record, JSON |
| **AI layer** *(optional)* | LiteLLM for hosted providers, Ollama for local — triage, explanation, and bounded agentic investigation with read-only tools |

Ghidra-backed cross-referencing and dynamic (detonation) analysis are designed
and not yet built — see [Status](#status).

---

## What it is not

BARE is a pre-release supply-chain hygiene tool. It is **not** a malware
analysis platform, a competitor-teardown tool, or an exploit development
environment.

- It optimises for finding secrets in *cooperative* artifacts — the ones you
  built. It does not defeat commercial protectors, bypass license checks, or
  circumvent DRM.
- It never produces exploits or weaponised output. Findings describe exposure
  and remediation.
- Uploads carry an authorization attestation — you own the artifact, or you are
  contractually authorized to test it — which is recorded in the audit log and
  stamped into every report. Enforcement is a setting
  (`BARE_REQUIRE_ATTESTATION`), shipped **off** so evaluating the tool has
  no friction. Turn it on before anyone analyses an artifact they did not build.

See [SECURITY.md](SECURITY.md) for the third-party-artifact (due diligence)
case.

## Deterministic spine, AI enhancement layer

This is the design constraint everything else defers to.

**Every finding is produced by a deterministic rule.** Same artifact, same rule
pack, same tool versions ⇒ byte-identical findings. Sort orders are explicit
throughout and the static analyzer's parallelism cannot affect its output.
Finding IDs are derived from content rather than from a sequence number, so
they are stable across re-runs and directly comparable across releases — which
is what lets the release gate ask "what is new since the last one?" and get a
set difference rather than a guess.

Every run records a manifest: artifact hash, rule-pack version and hash,
analyzer image digests, and tool versions. Two runs sharing a fingerprint must
produce identical findings, and the report prints it so you can check.

**The whole pipeline runs with `--no-llm` and still produces a complete,
useful report.** That is the CI default. If your model is down, your release
gate still works.

**The LLM sits strictly on top.** It triages (collapsing the false positives
that make binary secret scanning unusable), explains a finding in depth,
summarises a run, and can run a bounded, fully-cited investigation with
read-only tools. The remediation shown on a finding comes from the rule pack,
not from a model. It cannot invent a finding
that no rule anchored, and it cannot change a finding's severity, offsets, or
locations. The UI attributes every AI-derived field and has a
"deterministic view only" toggle. You can always answer *"would this finding
exist without the AI?"*

Bring your own model. Ollama runs locally on its own adapter; everything else
goes through LiteLLM, so OpenAI, Anthropic, Google, Azure, Bedrock, Vertex,
Groq, Mistral, DeepSeek, and the rest are a dropdown in the setup wizard rather
than a code change.

Egress is denied by default, and enforced where it cannot be worked around: a
provider whose endpoint is not local is never constructed under a deny policy,
and start-up refuses a config that holds one. That is deliberately coarser than
a per-request check — LiteLLM has no single interceptable choke point, so a
guarantee made at the HTTP call would hold for some vendors and silently not
for others. See ADR-0027.

## Binary composition analysis

BARE reads the bill of materials out of the artifact itself, not out of a
lockfile that may not describe what actually shipped:

- **Bundled package manifests** — `package.json`, Python `.dist-info/METADATA`,
  and `.nuspec` files that survived into the build.
- **Go build info**, read from the binary's own embedded module table. A Go
  executable carries its dependency graph whether or not anyone meant it to.

Components are identified by [Package URL](https://github.com/package-url/purl-spec)
across npm, NuGet, PyPI, Go, Cargo, Maven, and RubyGems, and the result is
served as CycloneDX 1.5 from `GET /api/runs/{id}/sbom`, downloadable from the
run page, or exported from the CLI:

```bash
bare scan dist/installer.exe --sbom sbom.cdx.json   # during a scan
bare sbom RUN_ID -o sbom.cdx.json                   # any run, later
bare sbom RUN_ID | jq '.components | length'        # stdout by default
```

Every component carries how it was identified — a `package.json` declaration
and a version banner scraped from a stripped binary are both useful and are not
the same fact, so `evidence.identity` records which. The document is derived
entirely from the stored run: no clock, no random serial, so two exports of one
run are byte-identical and can be hashed against a release or diffed between
builds.

**What it does not do**, so the SBOM is not read as more than it is: it finds
what the artifact *declares*. A statically-linked C library with no manifest and
no build info leaves no trace for it to find, and a zero-component result means
"nothing declared itself", not "nothing is bundled".

## Status

**Ingest and static analysis are complete, and so is the release gate.** Upload
an artifact through the dashboard or the CLI, it is unpacked recursively and
scanned in a locked-down container, and deterministic findings come back with
byte offsets, encoding, entropy, and remediation. A policy your repository owns
turns those into a ship / do-not-ship decision with a meaningful exit code.

The optional AI layer triages findings, explains one in depth, investigates one
agentically with read-only tools, and summarises a run. All of it is advisory
and none of it is required.

Reports come out as SARIF (for code scanning), PDF (for the release record),
CycloneDX (for the SBOM), and JSON.

Not yet built: Ghidra cross-references, dynamic analysis, and MCP servers.

You can verify the isolation boundary yourself — it reports what the analyzer
observed from *inside* its own container, which is the only measurement that
proves the profile actually applied:

```bash
make sandbox-check           # ./make.ps1 sandbox-check on Windows
```

See [CLAUDE.md](CLAUDE.md) for current status, known issues, and what is next,
and [feature-request.md](feature-request.md) for the bounty list — wanted
features, each scoped so it can be built on a branch and judged on whether it
works.

## Quick start

Requires Docker. That's it — no `.env` to hand-fill, no token to mint first.

```bash
docker compose up --build -d
```

That builds everything, analyzer images included — there is no separate image
step to remember before the first scan.

Open <http://localhost:3000>. A fresh deployment has no API token yet, so the
dashboard opens on a one-time setup wizard: click through it, and it mints the
first admin token and saves it for the dashboard itself — no restart, no `.env`
edit. A headless operator gets the same token from:

```bash
curl -X POST http://localhost:8000/api/setup/bootstrap
```

<http://localhost:8000/docs> has the API.

One setting is worth knowing about before you scan anything real:
**`BARE_RUN_ROOT_HOST`** must be an absolute *host* path, because the
worker spawns each analyzer as a sibling container through the Docker socket
and the daemon resolves bind mounts on the host, not inside the worker. The
default (`/var/lib/bare/runs`) is fine on Linux and macOS; on Windows,
copy `.env.example` to `.env` and set it to a Windows path (e.g.
`C:\bare\runs`). Get it wrong and analyzers get empty input directories
with no error at all — see the comment at the top of
[docker-compose.yml](docker-compose.yml) and
[docs/SETUP.md](docs/SETUP.md#2-get-the-code-and-configure).

For local development (source reload, running tests without Docker, an
Ollama-backed model), see [docs/SETUP.md](docs/SETUP.md), which also covers:

```bash
make check              # lint, type-check, unit tests — no Docker needed
make test-integration   # sandbox isolation tests — needs Docker
```

Analyzer images build and run as `:dev` by default. For a deployment, set
`BARE_ANALYZER_TAG` to a version or a git sha — both `make images` and
the orchestrator read it, so a build and a scan cannot disagree about which
image they mean.

On Windows, substitute `./make.ps1 <target>` for `make <target>`; the targets
are identical.

## Use it as a release gate

The point of scanning a shipped artifact is to stop it shipping. BARE
runs as a pipeline stage between the build and the release:

```bash
bare policy init                                    # once, per repository
bare scan dist/installer.exe --sarif findings.sarif  # in CI
```

It uploads the artifact, waits for the scan, evaluates a policy your repository
owns, and exits `0` pass, `1` blocked, `2` tool error, `3` inconclusive. The
pipeline stops on anything but `0`.

Three defaults make it something a team will actually leave switched on:

- **It fails on what the build introduced**, not on the backlog it inherited,
  so a product with 200 existing findings can adopt it today and stop the
  bleeding while the backlog burns down.
- **An incomplete scan is `inconclusive`, never a pass.** If an analyzer OOMs,
  the artifact was not fully examined, and saying otherwise is the failure that
  makes a gate worse than none.
- **AI triage cannot open the gate.** A model may reduce noise for a reviewer;
  it may not sign off a release.

See [docs/CICD.md](docs/CICD.md) for the integration design, a staged rollout
that does not get the tool uninstalled, and working workflows for GitHub
Actions, GitLab, Azure DevOps, and Jenkins in [examples/ci/](examples/ci/).

## Architecture

```
upload ──▶ API ──▶ orchestrator ──▶ one disposable container per analyzer
                                     unpack │ static │ ghidra │ dynamic
                                              │
                                    normalized evidence
                                              │
                                        correlator  ── dedupe, entropy, scoring
                                              │
                                     LLM layer (optional, advisory)
                                              │
                                    PDF · HTML · SARIF · CycloneDX · JSON
```

Analyzer containers never touch the network, never see the Docker socket, and
never hold provider API keys. The orchestrator is the only component with
egress, and it sends only redacted, size-bounded evidence.

Full detail in [ARCHITECTURE.md](ARCHITECTURE.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [CLAUDE.md](CLAUDE.md) | Current status, known issues, conventions |
| [docs/ADR.md](docs/ADR.md) | Architecture decision log, with rejected alternatives |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, pipeline stages, data model |
| [docs/CICD.md](docs/CICD.md) | Running BARE as a CI/CD release gate |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, responsible use |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What the sandbox defends against, and what it does not |

## Licence

Apache-2.0.
