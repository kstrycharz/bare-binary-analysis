# CLAUDE.md — BARE working document

The contract between sessions: current state, open debt, and the rules the code
is held to. Update at the end of every working session.

Keep it under ~300 lines and readable start to finish. Architecture
decisions live in [docs/ADR.md](docs/ADR.md) — append-only, and it would
otherwise swallow this file.

A running `docs/JOURNAL.md` holds the session-by-session account of what was
built and what broke. It is gitignored: useful while building, not something a
reader of this repository wants. Anything from it worth keeping is promoted to
the ADR log.

---

## 1. Project overview

BARE (Binary Analysis & Reverse Engineering) is a self-hosted,
air-gap-capable analysis platform for the binaries a company is about to
ship — installers, executables, DLLs, firmware images, ELF binaries,
embedded-device update bundles. It detonates them inside
disposable Docker sandboxes, reverse engineers them with standard open-source
tooling, and reports on secrets exposure, sensitive data leakage, and
unintended IP disclosure before the artifact reaches a customer. It fills the
gap between source-code scanning, which everyone does, and what is actually
embedded in the compiled output, which almost nobody checks.

The design premise is that the build pipeline leaks: CI environment variables
end up in strings tables, debug builds ship PDB paths exposing internal
directory trees and developer usernames, embedded vendors hardcode provisioning
credentials because the device has no other way to bootstrap, and installers
bundle config defaults with real staging tokens. The governing architectural
constraint is **deterministic spine, AI enhancement layer** (§2.5 of the
brief): every finding comes from a deterministic rule and the whole pipeline
runs usefully with the LLM disabled. The model triages, explains, and
investigates on top of that spine — it never invents a finding.

---

## 2. Current status

**Milestone: M1 — Ingest & static core. Complete. Plus most of M3 (BYOLLM:
local and cloud providers, triage, explain, summarize, discovery) and the M4
release gate, both pulled forward so the product is usable in a pipeline.**

Working end to end today: upload an artifact through the dashboard or the CLI,
it is scanned in a locked-down container, and deterministic findings appear
with offsets, encoding, and remediation. Optional AI triage classifies them,
explains individual findings, investigates them agentically with read-only
tools, and summarises a run. A release policy turns
those findings into a ship / do-not-ship decision with a meaningful exit code,
so BARE is a build-pipeline stage gate and not only a dashboard. Analyzer
output is kept per stage, redacted at write time (ADR-0032); `bare waive` writes
waivers the gate will honour, and `bare sbom-diff` compares two builds.

Deployment is two commands and no file editing — the dashboard's first-run
wizard mints the API token and optionally connects a model:

```bash
docker compose up --build -d   # then open http://localhost:3000
```

That builds the analyzer images too — they are Compose services that build and
exit, rather than something `make images` has to be remembered for (ADR-0028).

```bash
# as a release gate
uv run bare policy init
uv run bare scan dist/installer.exe --sarif bare.sarif
```

See [docs/CICD.md](docs/CICD.md) for the pipeline integration design and
working workflows for GitHub Actions, GitLab, Azure DevOps, and Jenkins.

See [docs/SETUP.md](docs/SETUP.md) for the full walkthrough.

**Previously: M0 — Foundation. Complete.**

What runs today, end to end, from a clean clone:

```bash
make install && make sandbox-check     # ./make.ps1 on Windows
```

- `SandboxSpec` / `SandboxDriver` / `DockerDriver` / watchdog / reaper are
  implemented, typed, and tested.
- The hello analyzer image builds and runs through the real driver inside a
  locked-down container.
- The isolation boundary is verified **from inside the container**: not root,
  read-only rootfs, read-only input mount, no TCP, no DNS, writable scratch and
  results.
- The watchdog kills a container that ignores SIGTERM; a memory hog is stopped
  and diagnosed as OOM rather than as a timeout.
- `docker compose` brings up Postgres, Redis, MinIO, API, two worker lanes,
  beat, and web. `/readyz` reports per-dependency health.
- CI runs lint, mypy strict, unit tests, the isolation suite, a gitleaks scan,
  the web build, and a stack-boots check.

Verified: 756 unit tests, 19 integration tests, `mypy --strict` clean on
`core/`, `ruff` clean, `next build` clean.

Not yet started: Ghidra and dynamic analysis (M5), MCP servers (M5), and the
`remediate` role.

**Next milestone: M5 — Ghidra cross-references and dynamic analysis. Reporting
(SARIF, PDF, CycloneDX) has landed; see `/api/runs/{id}/report.pdf` and
`/sbom`. `bare sbom RUN_ID` exports one for any past run.**

---

## 3. Architecture decisions

The full log, with rationale and rejected alternatives, is in [docs/ADR.md](docs/ADR.md).
Append-only; supersede rather than edit.

- **ADR-0001** — Stack is fixed by the brief (2026-08-17)
- **ADR-0002** — Sandbox interface before any analyzer (2026-08-17)
- **ADR-0003** — The driver removes containers; Docker `--rm` is never used (2026-08-17)
- **ADR-0004** — Seccomp is an allowlist, applied via inlined JSON (2026-08-17)
- **ADR-0005** — Tmpfs mounts carry explicit uid/gid/mode (2026-08-17)
- **ADR-0006** — Windows is a first-class development environment (2026-08-17)
- **ADR-0007** — Run root is mounted at the same absolute path on host and worker (2026-08-17)
- **ADR-0008** — Degraded analyzers return results; they do not raise (2026-08-17)
- **ADR-0009** — The driver translates host paths; it does not require identical mounts (2026-08-17)
- **ADR-0010** — Findings use a composite primary key (id, run_id) (2026-08-17)
- **ADR-0011** — The detection engine has no heavy dependencies (2026-08-17)
- **ADR-0012** — Triage cannot dismiss a finding at or above high severity (2026-08-17)
- **ADR-0013** — The dashboard proxies the API at runtime, not via a rewrite (2026-08-17)
- **ADR-0014** — Durations are measured with a monotonic clock (2026-08-17)
- **ADR-0015** — The release gate is a product surface, not a script (2026-08-18)
- **ADR-0016** — The gate fails on what the build introduced, not what it inherited (2026-08-18)
- **ADR-0017** — A model may not open the release gate (2026-08-18)
- **ADR-0018** — An incomplete scan is INCONCLUSIVE, never a pass (2026-08-18)
- **ADR-0019** — The policy travels to the server; findings do not travel to CI (2026-08-18)
- **ADR-0020** — click is pinned below 8.2 (2026-08-18)
- **ADR-0021** — Rules carry an explicit exclusion list, not negative lookaheads (2026-08-19)
- **ADR-0022** — The static analyzer parallelises inside one container (2026-08-19)
- **ADR-0023** — The API authenticates by default, with two scopes (2026-08-24)
- **ADR-0024** — Schema changes ship as migrations; start-up refuses a stale schema (2026-08-25)
- **ADR-0025** — A run is claimed with a conditional UPDATE, committed immediately (2026-08-25)
- **ADR-0026** — Response models are constructed, not validated from ORM objects (2026-08-25)
- **ADR-0027** — LiteLLM is the transport; the air gap is enforced above it (2026-08-26)
- **ADR-0028** — Analyzer images are Compose services, built by `docker compose up` (2026-08-27)
- **ADR-0029** — The API is the only migrator, and everything else waits for it (2026-08-27)
- **ADR-0030** — The packaged LLM config ships inert (2026-08-27)
- **ADR-0032** — Analyzer logs are retained in object storage, redacted at write time (2026-09-11)

---

## 4. Progress log

Kept in `docs/JOURNAL.md`, which is gitignored — what was built each session,
what broke, and why. Out of this file so the instructions below stay findable,
and out of the repository because it is build-time working material. Promote
anything durable to [docs/ADR.md](docs/ADR.md).

---

## 5. Next steps

The gate, authentication, and reporting have all landed. What is left is
mostly about the tool being *lived with* rather than demonstrated.

1. **Gate the gate in this repo's own CI.** BARE should scan its own
   built artifacts on every release tag. Dogfooding is the fastest way to find
   out which parts of `docs/CICD.md` are wrong, and it is the one claim in the
   README that nothing currently verifies.
2. **Plaintext retention needs its TTL.** §9 promises encryption at rest, a
   TTL, and auto-purge. None of the three exists, so a run scanned with
   retention on leaves real secrets in Postgres indefinitely. The UI says so at
   the point of choosing, which is not the same as the promise being kept.
   In review as #12.
3. **The Go string-blob problem** (§6). It affects every rule on every Go
   binary and needs a Go-aware splitter, not a per-rule patch.
4. **Decide about `remediate`.** It is routable and described in the settings
   UI as unwired. Either wire it or drop it from `EDITABLE_ROLES`; leaving a
   configurable role that does nothing is how the explain/summarize gap started.

Then: the run-comparison view in the dashboard, which is the same baseline
computation the gate already does, surfaced for a human rather than a pipeline.

---

## 6. Known issues & tech debt

| Severity | Item |
| --- | --- |
| Medium | `PodmanDriver` and `GvisorDriver` raise `NotImplementedError`. Scheduled M6. Rootless Podman is a hard requirement for some enterprises. |
| Medium | `NetworkMode.SINKHOLE` raises in `DockerDriver._build_create_kwargs`. Dynamic analysis lands M5. Failing loudly is deliberate — a silent fallback to a bridge would hand an artifact real egress. |
| Medium | The seccomp allowlist has only been exercised against a slim Python image. Ghidra (JVM) and Wine are likely to need additions. Validate per image as they are built; do not weaken the profile globally in response to one failure. |
| Medium | `_active_run_ids()` in `core/orchestrator/tasks.py` returns `None` until the `runs` table exists, degrading the reaper to age-based cleanup. M1 is complete and it is still not wired. |
| Medium | The artifact tree in the run detail response is capped at 500 nodes. The count stays exact and every artifact is still scanned, but there is no way to page through the rest — a real explorer needs its own paginated endpoint. |
| High | Context snippets mask only their own finding's value. Neighbouring secrets in the 60-byte window — the other half of a credential pair, or a UTF-16 string that reads as `g.h.p._...` — are stored in the clear, and triage and explain send them to the model as "value masked". `llm_calls.prompt_rendered` keeps the exact prompt, so past calls hold them too. Fix in review: #14. |
| High | `DockerDriver` reports OOM only when Docker sets `State.OOMKilled`. A process killed quickly under cgroup v2 can exit 137 without it and is reported `COMPLETED`, so the stage is not degraded and the gate can pass a scan that did not finish (ADR-0018). This is what makes `test_memory_hog_is_stopped_and_diagnosed_as_oom` flaky in CI. |
| Medium | The audit log records uploads, attestations, rejected credentials, token changes, finding status changes, and run recovery — not plaintext reveals, settings changes, report exports, or suppressions. Retained values come back inside ordinary findings responses with no record of who looked. See the `audit-completeness` bounty. |
| Low | `ManifestOut` exposes neither `recon` nor `components`. Components are reachable as CycloneDX through `/api/runs/{id}/sbom`; the recon inventory is exposed by no endpoint at all (see the `re-view` bounty). |
| Low | `make airgap-bundle` exits 1 with a pointer to its milestone (M6). |
| Low | Base image digests are pinned inline in Dockerfiles. `make refresh-digests` prints current values but does not rewrite them. |
| Low | `beat` has no healthcheck: it answers no `celery inspect ping` and the base image has no `pgrep`. Both worker lanes are covered (ADR-0029); a wedged beat is still only visible in logs. |
| Medium | Go binaries store strings in one contiguous blob with no separators, so the printable-run extractor merges adjacent unrelated strings and a regex can match across the seam. Observed: `…per_page=30reflect:` and `dllsecur32.dllshell32.dlluserenv.dlltime`. Affects every rule on Go artifacts; needs a Go-aware string splitter, not a per-rule fix. |
| Medium | `internal-hostname` matches Go package paths — `eq.internal`, `hash.internal`, `x509.local` — because `internal` is a reserved Go package name. 46 hits in one binary, all noise. Medium severity so it does not block, but it pads the report. |
| Medium | The release gate has no native GitHub Action or GitLab component; `docs/CICD.md` calls the CLI directly, which works everywhere but is more wiring than a marketplace action. |
| Medium | `first_seen_run_id` on `Finding` is never populated. The gate computes "is new" from the baseline run's id set instead, which is correct but means the column is dead weight. |
| Low | `click` is pinned to 8.1.8 to work around typer 0.15.1 (ADR-0020). Revisit when typer supports click 8.2+. |
| Medium | Plaintext retention has no TTL and no auto-purge, and nothing encrypts it at rest. A run scanned with "Retain full plaintext values" leaves real secrets in Postgres indefinitely. The UI says so at the point of choosing, but §9 promises a TTL that does not exist yet. Fix in review: #12. |
| Medium | Investigation quality tracks the model hard. On a local 14b the loop runs correctly — it searches, probes encodings, and terminates — but the conclusion is often generic ("review the file and ensure it does not contain sensitive information"). The mechanism is sound; the prose needs a better model or a larger `num_ctx`, and the default routing sends `investigate` to the fast model. |
| Low | An investigation re-reads no earlier tool output once it falls outside `MAX_CONTEXT_TURNS`; the model is told steps were omitted but cannot get them back. Fine at 12 steps, wrong if the cap ever rises much. |
| Medium | The `remediate` role is routable and described in the settings UI as not-yet-wired, but nothing calls it. Either wire it or drop it from `EDITABLE_ROLES`. |
| Low | `explain` and `summarize` have no cache: asking twice costs two calls. Triage caches by prompt hash within a pass; these do not, because they are user-initiated and low-volume. |
| Low | Cloud provider adapters are unit-tested against their wire shapes but only OpenAI has been exercised against the live API (a deliberate 401). Anthropic and Google are untested end to end. |

---

## 7. Dev environment

Requires Docker, [uv](https://docs.astral.sh/uv/), and Node 22.
Windows: use `./make.ps1 <target>` — same target names.

```bash
make install            # sync Python deps into .venv
make images             # build analyzer images
make check              # lint + mypy + unit tests; no Docker needed
make test-integration   # sandbox isolation suite; needs Docker
make sandbox-check      # M0 acceptance: probe through the real sandbox
make dev                # full stack with reload
make down / make clean  # stop / stop and delete volumes
```

Non-obvious things worth knowing:

- **Analyzer image tags come from `BARE_ANALYZER_TAG`** (default `dev`).
  One variable feeds the Makefile, `make.ps1`, and `core/sandbox/images.py`, so
  the build and the orchestrator cannot disagree about which image they mean.
  `BARE_<NAME>_IMAGE` still takes a full reference and wins, which is how
  a digest gets pinned.
- **`BARE_RUN_ROOT` must be an absolute host path.** The worker spawns
  analyzer containers as siblings via the Docker socket; the daemon resolves
  their bind mounts on the *host*. Mismatch it and analyzers silently get empty
  input directories. See ADR-0007.
- **The isolation probe is the real test.** `bare sandbox hello` reports
  what the container observed from the inside. Inspecting the daemon's view of
  a container's config proves nothing about whether the config took effect.
- **A single analyzer test run:**
  `uv run pytest tests/integration -k probe -v`.
- **Seccomp failures look like mysterious `EPERM`s** in an analyzer, usually
  during process start. Reproduce with `seccomp_profile=None` on the spec to
  confirm the profile is the cause before editing it.
- **Windows bind mounts** work through Docker Desktop but do not carry POSIX
  ownership, so `_make_writable()` is a no-op there and the container sees a
  permissive mount. On Linux the results directory is chowned to uid 10001.

---

## 8. Conventions

- **Commits:** Conventional Commits. Small and atomic. Feature branches; never
  commit directly to `main`.
- **Tests:** every non-trivial module gets tests in the same commit. Unit tests
  must not require Docker. Integration tests are marked `@pytest.mark.integration`
  and skip cleanly when Docker is absent.
- **Types:** `mypy --strict` on `core/`. New modules go under `core/` unless
  they are genuinely API, CLI, or reporting concerns.
- **Style:** ruff with line length 100. Comments explain *why*, especially
  where the obvious implementation is wrong (see the `--rm` and tmpfs notes).
- **Dependencies:** prefer boring and well-supported. Pin exactly. Justify every
  new one in the ADR log.
- **Placeholders raise.** Nothing is silently stubbed. A placeholder raises
  `NotImplementedError` naming its milestone, and appears in §6.
- **Determinism:** sort orders explicit everywhere. Finding IDs are
  content-derived, never sequence numbers. Parallelism must not affect output.

---

## 9. Do not do

Product guardrails, from §2 and §14 of the brief:

- **No offensive capability.** No exploit generation, no PoCs, no
  anti-anti-debug, no unpacking of commercial protectors, no license-check
  bypass, no DRM circumvention. Findings describe exposure and remediation,
  full stop. If a prompt to the LLM layer asks for any of it, the system prompt
  refuses.
- **No finding without a deterministic anchor.** The LLM may suppress, demote,
  rank, explain, and investigate. It may never create a finding, change a
  `value_hash`, offsets, or locations, or lower severity below a rule's floor
  for critical items.
- **Never require the LLM.** `--no-llm` must always produce a complete, valid,
  useful report. That is the CI default.
- **Never send candidate secret plaintext to a remote provider.** Shape,
  entropy, rule name, masked context, offsets only. Local providers may receive
  plaintext solely under a distinct, explicit opt-in.
- **Analyzers get no network, no Docker socket, no API keys.** The orchestrator
  is the only component with egress.
- **No attestation, no ingestion.** It is recorded in the audit log and printed
  in every report.
- **Never store discovered secrets in plaintext by default.** Hashed and masked
  unless plaintext retention is explicitly enabled per run, encrypted at rest,
  with a TTL and auto-purge.
- **Never commit a real credential to this repo.** Corpus fixtures use
  provably-invalid shapes (`AKIAIOSFODNN7EXAMPLE`). gitleaks runs in CI.

Engineering dead ends already explored, so they are not re-explored:

- Docker `--rm` for analyzer containers — races log collection (ADR-0003).
- Passing a seccomp *path* through the Docker API — silently applies no
  profile (ADR-0004).
- Relying on an image's `chown` for tmpfs scratch directories — the mount masks
  it (ADR-0005).
- A named volume for the run root — sibling containers resolve bind paths on
  the host (ADR-0007).
