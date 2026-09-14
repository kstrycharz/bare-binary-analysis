# Threat model

A full treatment lands with M6. This is the honest working version: what the
sandbox defends against today, what it does not, and where the residual risk
sits. Nothing here is aspirational — where a control is not yet implemented it
says so.

## Assets

| Asset | Why it matters |
| --- | --- |
| Submitted artifacts | Customer crown-jewel IP. Unreleased builds, firmware, source paths |
| Discovered secrets | Live credentials, concentrated in one database |
| The host | Runs the worker, which holds the Docker socket |
| Audit log and attestations | The evidence chain a compliance officer relies on |
| LLM egress path | The only route by which artifact-derived data leaves the network |

## Actors

1. **The operator** — trusted, authenticated, authorized. Their mistakes matter
   more than their malice.
2. **The submitted artifact** — *semi-trusted*. Built by the operator's own
   organisation, so not assumed hostile, but assumed capable of arbitrary
   behaviour once executed or parsed. This is the central assumption; see
   Non-goals.
3. **A network attacker** — cannot reach anything by default; the reference
   deployment exposes only the API and dashboard.
4. **A malicious LLM provider** — receives whatever the redaction layer sends,
   and nothing else.

## What the sandbox defends against

Each control is verified by a test in `tests/integration/test_sandbox_isolation.py`
that asserts from *inside* the container. The daemon's description of a
container's configuration is not evidence that the configuration took effect.

| Threat | Control | Verified |
| --- | --- | --- |
| Artifact exfiltrates data to the internet | `network_mode=none`; no interface exists | ✅ TCP connect and DNS both fail |
| Artifact writes a persistent implant | Read-only rootfs; tmpfs is `nosuid,nodev`, `/tmp` also `noexec` | ✅ rootfs write fails |
| Artifact tampers with the input it is judged on | `/input` mounted read-only | ✅ write fails |
| Artifact escalates to root inside the container | `user=10001:10001`, `cap_drop=ALL`, `no-new-privileges` | ✅ uid is 10001 |
| Artifact escapes via kernel or namespace primitives | Seccomp allowlist denies `ptrace`, `mount`, `unshare`, `setns`, `bpf`, `perf_event_open`, `userfaultfd`, `io_uring`, the module and keyring families | ✅ `unshare(CLONE_NEWUSER)` and `ptrace` both EPERM from inside |
| Artifact takes the host down by exhausting memory | `mem_limit` with `memswap_limit` equal, so it OOMs rather than swapping | ✅ memory hog is stopped, reported as OOM |
| Artifact hangs the pipeline | Watchdog: SIGTERM → grace → SIGKILL; run continues with the analyzer marked | ✅ SIGTERM-ignoring container is killed |
| Artifact fork-bombs | `pids_limit=512`, `nproc` ulimit | ⚠️ configured, not yet asserted |
| Artifact reaches the Docker socket and escapes to the host | Socket is never mounted into analyzers; the spec validator rejects any attempt | ✅ spec validation test |
| Artifact reads another run's data | Mounts confined to the run root; one staging and one results directory per run | ✅ mount confinement test |
| Zip bomb exhausts disk | Depth cap, cumulative byte cap, file-count cap across the whole extraction tree | ❌ **not implemented** — arrives with S2 in M2 |
| Crashed orchestrator leaks containers | Reaper sweep on run liveness and age | ✅ unit tests; live sweep verified |

## What it does not defend against — and why

**Anti-analysis and hostile artifacts.** BARE does not implement
anti-anti-debug, commercial protector unpacking, or evasion detection. An
artifact deliberately built to defeat analysis will defeat this analysis. That
is a deliberate scope decision, not an oversight: the tool exists to find
secrets your build pipeline leaked into artifacts *you* built. Pointing it at
genuinely hostile malware is out of scope and, with dynamic analysis enabled,
unsafe.

**Kernel vulnerabilities.** Containers share the host kernel. Seccomp plus
dropped capabilities plus a non-root user substantially reduces the reachable
attack surface, but a container escape via a kernel bug is possible in
principle. Operators wanting a second boundary should wait for the gVisor driver
(M6) or run the worker on a dedicated, isolated host.

**The worker's Docker socket.** This is the largest residual risk in the
system, so it is stated plainly rather than buried:

> The worker mounts `/var/run/docker.sock`. Socket access is root-equivalent on
> the host. Anyone who achieves code execution *in the worker process* owns the
> host.

It is not avoidable in this architecture — something has to spawn analyzer
containers — but it is bounded:

- Analyzers never see the socket. They run in separate containers with their own
  hard boundary, which is the entire reason that boundary exists.
- The worker parses analyzer *output*, not artifact bytes. Parsers that touch
  untrusted binary data belong inside analyzer containers, and any new code that
  parses artifact content in the worker process is a bug worth treating as a
  vulnerability.
- Celery accepts JSON only. Pickle would let anything that can reach Redis
  execute code in the worker.
- Mitigations: run the worker on a dedicated host or node pool, and use the
  rootless Podman driver when it lands (M6).

**Sensitive data at rest.** Secrets are hashed and masked by default, but the
findings database is still a high-value target. Encrypt the volume, restrict
network access to Postgres, and keep plaintext retention off unless a specific
run needs it. When a run does retain values they are AES-GCM ciphertext under a
key held outside the database, served only until the run's deadline, and then
purged (ADR-0032) — which protects a leaked backup or replica, not a compromised
API host, since that host holds the key.

**Denial of service by an authorized user.** Rate limiting and per-tenant quotas
are not implemented. The reference deployment assumes an internal, authenticated
user base.

## Dynamic analysis (M5) — additional exposure

Dynamic analysis **executes the artifact**. It is off by default, opt-in per
run, and the exposure is categorically different from static analysis:

- The artifact runs real code, under Wine or qemu-user with strace/ltrace.
- It gets a network namespace whose only reachable peer is a sinkhole container
  (fake DNS plus a catch-all responder). It never reaches a real network. Every
  DNS query and connection attempt is recorded as evidence — "the installer
  phones `provisioning-internal.corp.example`" is a finding in itself.
- Installers are run in silent mode to observe what they drop.

Enable it only on a host you are willing to treat as compromised. The sinkhole
netns is a containment measure, not a guarantee.

## The LLM trust boundary

The question a security team will actually ask is *"what leaves my network?"*
The answer must be precise, so it is enforced in code rather than by convention:

- Egress policy is enforced at the HTTP-client layer. A request to a
  non-allowlisted host raises. Air-gapped mode makes cloud adapters fail at
  config-validation time, not at request time.
- Candidate secret plaintext is never sent to a remote provider — shape,
  entropy, rule name, masked context, and offsets only. Local providers may
  receive plaintext solely under a distinct, explicit opt-in.
- Identified customer data (emails, names, IPs) is redacted from context windows
  before remote calls.
- Every outbound call is logged with provider, model, role, token counts, prompt
  hash, and redaction level, as a replayable record.
- `--llm-dry-run` renders every prompt to disk without sending, so the boundary
  can be audited before the tool is approved.
- The MCP servers enforce the same run-scoped authorization and redaction as the
  internal pipeline. An MCP client must not be a way around the boundary.

Status: designed, scheduled for M3. Until then the pipeline is
deterministic-only and makes no outbound calls at all.

## Known gaps

| Gap | Severity | Plan |
| --- | --- | --- |
| Zip-bomb and recursion budgets not implemented | High once S2 exists | M2, with S2 unpacking |
| Seccomp profile only exercised against a slim Python image | Medium | Validate per analyzer image as Ghidra and Wine land |
| Fork-bomb containment configured but not asserted | Low | Add a probe that spawns past `pids_limit` |
| No rootless runtime | Medium | Podman driver, M6 |
| No RBAC or SSO | Medium | M6 |
| No rate limiting or quotas | Low | Post-M6 |
| Reaper cannot see run liveness until the `runs` table exists | Low | M1; degrades safely to age-based cleanup |
