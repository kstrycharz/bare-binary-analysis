# Architecture

## The governing constraint

BARE is a deterministic scanner with a very good AI investigator attached.
It is not an AI tool with rules bolted on, and that distinction is
architectural rather than rhetorical. Everything below defers to it.

**The deterministic spine.** Every finding is produced by a rule. Same artifact
+ same rule pack + same tool versions ⇒ byte-identical findings, enforced by a
CI test that runs the corpus twice and diffs normalized JSON. Every run writes a
manifest — artifact SHA-256, rule-pack version and hash, analyzer image digests
(not tags), tool versions, BARE version — and the report prints it.
Finding IDs are content-derived from `hash(rule_id + value_hash + artifact_path
+ offset)`, never sequence numbers, so they are stable across re-runs and
comparable across releases. Sort orders are explicit everywhere; analyzers write
independent evidence rows and the correlator sorts before merging, so
parallelism cannot leak scheduling order into results.

**The AI enhancement layer.** The LLM may suppress or demote a finding to
`needs_review`, rank and cluster, explain, propose remediation, and drive a
bounded deep investigation. It may not create a finding without a deterministic
anchor, alter a `value_hash`, offsets, or locations, lower severity below a
rule's floor for critical items, or be required for a run to complete. The whole
pipeline runs with `--no-llm` and produces a complete, valid report. That is the
CI default.

---

## Component overview

```
                 ┌────────────────────────────────────────────────┐
   upload ──────▶│  API (FastAPI)   auth, attestation, run mgmt    │
   CI webhook    └───────┬────────────────────────────────────────┘
                         │ enqueue
                 ┌───────▼────────┐        ┌──────────────────────┐
                 │ Orchestrator   │───────▶│ Postgres / MinIO     │
                 │ (Celery beat + │        └──────────────────────┘
                 │  canvas graph) │
                 └───────┬────────┘
                         │ one container per analyzer per artifact
         ┌───────────────┼───────────────┬──────────────────┐
         ▼               ▼               ▼                  ▼
   ┌──────────┐   ┌────────────┐   ┌───────────┐     ┌────────────┐
   │ unpack   │   │ static     │   │ ghidra    │     │ dynamic    │
   │ 7z       │   │ strings    │   │ headless  │     │ wine       │
   │ binwalk  │   │ yara, capa │   │ analyzeHdl│     │ strace     │
   │ msitools │   │ LIEF       │   │           │     │ sinkhole   │
   └────┬─────┘   └─────┬──────┘   └─────┬─────┘     └─────┬──────┘
        └───────────────┴────────────────┴─────────────────┘
                         │ normalized Evidence records
                 ┌───────▼────────┐
                 │ Correlator     │  dedupe, entropy, cross-file linking
                 └───────┬────────┘
                         │ candidates + minimal context windows
                 ┌───────▼────────┐        ┌──────────────────────┐
                 │ LLM Layer      │◀──────▶│ Provider adapters     │
                 │ triage         │        │ Ollama/vLLM (default) │
                 │ explain        │        │ OpenAI/Anthropic/     │
                 │ remediate      │        │ Google/Azure/Bedrock  │
                 └───────┬────────┘        └──────────────────────┘
                         │
                 ┌───────▼────────┐
                 │ Reporting      │  PDF, HTML, SARIF, CycloneDX, JSON
                 └────────────────┘
```

**The hard rule:** analyzer containers never touch the network, never see the
Docker socket, and never hold provider API keys. The LLM layer runs in the
orchestrator process, is the only component with egress, and receives only
redacted, size-bounded evidence.

---

## The sandbox boundary

Implemented in `core/sandbox/`. This is the load-bearing wall — everything else
in the system trusts it, and it was built and tested before any analyzer
existed because retrofitting an abstraction under N analyzers means rewriting
all N.

### SandboxSpec

A frozen dataclass describing one container run, and the only way to ask for
one. Declaring the isolation posture in a single reviewable place means a test
can assert "no analyzer ever gets network access" by inspecting specs rather
than by reading every analyzer module.

| Field | Default | Why |
| --- | --- | --- |
| `network` | `none` | Static analyzers have no reachable network at all |
| `read_only_rootfs` | `True` | Nothing an analyzer writes survives outside tmpfs |
| `user` | `10001:10001` | Never root, even inside the container |
| `cap_drop` | `["ALL"]` | `cap_add` is rejected outright for analyzers |
| `no_new_privileges` | `True` | Blocks setuid escalation |
| `seccomp_profile` | `analyzer.json` | Syscall allowlist; see below |
| `mem_limit_bytes` | 4 GiB | Ghidra overrides upward |
| `nano_cpus` | 2 CPU | Prevents one analyzer monopolising the host |
| `pids_limit` | 512 | Fork-bomb containment |
| `tmpfs` | `/tmp` 2G noexec, `/work` 8G | Explicit uid/gid/mode — see ADR-0005 |
| `timeout_s` | 900 | Per-analyzer override |

`spec.validate()` runs before every container and refuses anything that would
weaken the boundary — root, missing `cap_drop: ALL`, a writable `/input`, more
than one writable mount, or a Docker socket mount. `with_overrides()` guards the
isolation fields so an analyzer definition cannot loosen them by accident.

### Mounts

Exactly two, and nothing else is shared:

- `/input` — read-only bind of the per-run staging directory
- `/output` — the single writable bind, where results come back

Mount sources are confined to the configured run root, so a bug in an analyzer
definition cannot mount `/`.

**Host path translation.** When the orchestrator is itself containerised it
spawns analyzers as *siblings* through the host Docker socket, and the daemon
resolves their bind paths on the host. The driver therefore holds two views of
the run root — `run_root` (as this process sees it) and `host_run_root` (as the
daemon sees it) — and translates. Mounting both at an identical path would be
simpler but is impossible on Windows, where a host path is `C:\...`. Getting
this wrong yields analyzers with empty input directories and no error at all.

### Seccomp

`sandbox/profiles/analyzer.json` is an **allowlist**: the default action is
EPERM and permitted syscalls are named. A denylist would silently admit every
syscall a future kernel adds.

The driver reads the profile and passes its *contents* in `security_opt`. The
Docker CLI reads profile files client-side, but the API expects the JSON —
passing a path through the API applies no profile, with no error, which is the
worst possible failure for a security control.

Absent by design: `ptrace` and `process_vm_*`, the mount and namespace families
(`mount`, `pivot_root`, `chroot`, `unshare`, `setns`, `fsopen`/`move_mount`),
`bpf`, `perf_event_open`, `kexec_load`, the module family, the kernel keyring,
`userfaultfd`, `io_uring_*`, and the host-affecting calls (`reboot`, `swapon`,
`settimeofday`, `quotactl`). Socket syscalls *are* permitted — network isolation
comes from the netns, and denying them breaks libc and the JVM for no gain.
`clone3` returns ENOSYS rather than EPERM so glibc falls back to `clone`.

The dynamic analyzer needs `ptrace` and gets its own profile in M5.

### Watchdog

Driver-agnostic escalation in `core/sandbox/watchdog.py`: wait → SIGTERM →
grace → SIGKILL. Split out from the driver because the sequence is the part
most likely to be subtly wrong, and it is far easier to test against a fake
handle with a fake clock than against a real daemon at 900-second timeouts.

A hung analyzer is terminated, marked `timeout`, and the run continues. Ghidra
will hang on some binaries; that must cost one degraded analyzer, not the whole
scan. `SandboxDriver.run()` returns degraded results rather than raising —
it raises only for an invalid spec, which is programmer error.

Swap is pinned to the memory limit, so a runaway allocation surfaces as `OOM`
rather than as an unbounded hang the watchdog would misdiagnose as a timeout.

### Reaper

A crashed orchestrator leaks containers holding memory the next run needs. The
reaper sweeps everything labelled `bare.managed`, removing containers
whose run is no longer active or which have outlived `max_age`.

It is conservative in one direction on purpose: it never removes a container
whose run id is in the active set, because a legitimately long Ghidra job must
not vanish mid-run. Age overrides liveness, since a container running past
`max_age` has outlived its watchdog — which means the watchdog process is gone.
When liveness cannot be determined it degrades to age-based cleanup only rather
than guessing.

---

## Analysis pipeline

Each stage is a Celery task producing `Evidence` rows.

| Stage | What it does | Milestone |
| --- | --- | --- |
| **S0 Ingest** | Hash (SHA-256/SSDEEP/TLSH), record attestation, store in MinIO, dedupe by hash | M1 |
| **S1 Identify** | LIEF/pefile/pyelftools, arch, packer ID, and build metadata: PE Rich header, Go build info, .NET attributes, PDB path, code-signing chain and expiry | M1 |
| **S2 Unpack** | Recursive: NSIS, InnoSetup, MSI, CAB, 7z, squashfs, cpio, UEFI/UBI/JFFS2, APK/IPA, ASAR, PyInstaller, .NET, JAR, UPX. Every extracted file re-enters S1 as a child artifact | M2 |
| **S3 Static** | strings (ASCII **and** UTF-16LE) with offsets, secret rules, YARA, sliding-window entropy, embedded certs and private keys, capa, config/resource extraction, symbol and RTTI leakage, PDB and DWARF source paths | M1–M2 |
| **S4 Deep RE** | Ghidra headless: xrefs to flagged strings, hardcoded crypto constants, decompiled context windows | M5 |
| **S5 Dynamic** | Opt-in. Wine or qemu-user under strace/ltrace with a sinkhole netns | M5 |
| **S6 Correlate** | Dedupe across the artifact tree, score by entropy/confidence/context, filter against the false-positive corpus | M2 |
| **S7 Triage** | LLM classification, explanation, remediation | M3 |
| **S8 Report** | PDF, HTML, SARIF, CycloneDX, JSON | M4 |

The table is the design; the milestone column is when each part was planned,
not a claim that all of it shipped. Not built today: SSDEEP/TLSH hashing, YARA,
UPX unpacking, RTTI and Rich-header extraction, HTML reports, and all of S4 and
S5. Reports ship as PDF, SARIF, CycloneDX, and JSON. The README's "Under the
hood" table lists the tools that actually do the work.

Two details that decide whether the tool is useful:

- **UTF-16LE strings.** Windows binaries hide half their secrets in wide
  strings, and a surprising number of tools only scan ASCII.
- **The false-positive corpus.** Public test keys, `example.com`, RFC sample
  values, `AKIAIOSFODNN7EXAMPLE`, Windows SDK sample GUIDs. This is the
  difference between a tool people use and a tool people mute.

Deterministic rules stay deliberately over-inclusive — missing a live key is
much worse than surfacing a dud — and LLM triage is what makes that tolerable.
The precision/recall harness tracks rule-only recall and post-triage precision
as separate metrics.

---

## Data model

Core tables: `runs`, `run_manifests`, `run_stages`, `artifacts`
(self-referencing tree via `parent_id`), `evidence`, `findings`,
`finding_locations`, `llm_calls`, `audit_log`, `suppressions`, `api_tokens`.
An investigation's conclusion and replayable tool-call trace live on the
finding (`llm_investigation`, `llm_investigation_steps`) rather than in tables
of their own. Rules are YAML under `detections/`, not rows, and there is no
`users` table: access is by scoped API token (ADR-0023).

```
Finding
  id, run_id, rule_id, category, title
  severity(critical|high|medium|low|info)     ← from the rule, never the model
  confidence(0-1)
  status(open|confirmed|false_positive|accepted_risk|fixed)
  value_masked, value_hash, entropy
  detected_by(rule|llm|both)
  locations[] → {artifact_id, path_in_tree, offset, section, xref_function}
  context_snippet
  llm_assessment{verdict, reasoning, model, timestamp}   ← separate, attributed
  remediation_md, first_seen_run_id, suppressed_by, cwe, tags[]
```

The artifact tree is a real tree, not a flat list: the report must be able to
say "in `setup.exe` → `app.7z` → `resources/app.asar` → `config/prod.json`".

Suppressions key on `value_hash` + rule + artifact-path pattern, live in the
`suppressions` table, and are applied during every scan. The planned checked-in
`.bare-ignore.yaml` that would carry them between deployments does not exist
yet. If a user cannot suppress a known-benign finding once and have it stay
suppressed, they stop using the tool by week three.

Run diffing is first-class, not an afterthought — "what is new since the last
release" is the question CI actually asks.

---

## The BYOLLM layer

`LLMProvider` exposes `complete()`, `capabilities()`, `health()`, and
`count_tokens()`. There are two adapters: `OllamaProvider` for local models, and
`LiteLLMProvider` for every hosted vendor — OpenAI, Anthropic, Google, Azure,
Bedrock, Vertex, Groq, Mistral, DeepSeek, and anything with an OpenAI-compatible
endpoint (ADR-0027). Streaming, native tool calls, and embeddings are not part
of the interface.

`capabilities()` reports native tool calling, structured output, context window,
and max output tokens, and the orchestrator degrades gracefully: no tool calling
falls back to a prompted ReAct loop, no structured output falls back to
constrained JSON with a repair pass. Someone will point this at a 7B local model
and it must still work.

Role-based routing in `config/llm.yaml` sends high-volume triage to a cheap
local model and low-volume explanation to a frontier model.

### The trust boundary

Customers are sending their crown-jewel IP. This layer is why they will or will
not adopt the tool.

- Egress policy is enforced in code, not by convention (`EgressPolicyGuard`,
  ADR-0027): loopback and private addresses count as local, anything else raises
  under a deny policy, and air-gapped mode forbids every non-local provider.
- Candidate secret plaintext is **never** sent to a remote provider. Shape,
  entropy, rule name, masked context (`sk-live-••••••••••••4f2a`), and offsets
  only. Local providers may receive plaintext solely under a distinct, explicit
  opt-in.
  Until #14 lands, a snippet masks only its own finding's value, so a
  neighbouring secret can still reach the model.
- Customer data (emails, names, IPs) is **not** redacted beyond secret masking.
- Every outbound call is recorded in `llm_calls`: provider, model, role,
  locality, redaction level, prompt hash, the exact rendered prompt, response,
  and token counts. "What exactly did you send to OpenAI?" has a precise answer.
- There is no prompt dry-run mode yet; the recorded prompts are the review trail.

---

## Deployment

`docker compose` is the reference deployment; a Helm chart lands in M6.

[docs/CONTAINERS.md](docs/CONTAINERS.md) covers each container in operational
detail — healthchecks, failure modes, state, and which ones hold privilege.

| Service | Role |
| --- | --- |
| `api` | FastAPI. No Docker socket — it does not spawn containers |
| `worker` | Celery: `control`, `unpack`, `static`, `llm`. Concurrency 4 |
| `worker-heavy` | Celery: `ghidra`, `dynamic`. Concurrency 1 |
| `beat` | Periodic tasks, currently the reaper sweep |
| `postgres` | Findings, artifacts, runs, audit log |
| `minio` | Uploaded artifacts and extracted files; S3-compatible, runs air-gapped |
| `redis` | Celery broker and result backend |
| `web` | Next.js dashboard |

Queues are split by analyzer class because Ghidra is slow, memory-hungry, and
the most likely thing to hang. On a shared queue one wedged Ghidra job starves
the string scanners that produce most findings.

The worker mounts the Docker socket, which is root-equivalent on the host. It is
the only component that does, it is deliberate, and it is documented in
[THREAT_MODEL.md](THREAT_MODEL.md) — it is also precisely why analyzers run in
hard-isolated containers instead of in the worker process.
