# Architecture decision log

Append-only. Supersede rather than edit — a decision that was wrong is part of
the record, and the reasoning that led to it usually recurs.

Split out of [CLAUDE.md](../CLAUDE.md) on 2026-08-24: the log had grown past the
300-line mark and was crowding the working contract out of its own file. Nothing
was edited in the move.

---

### ADR-0001 — Stack is fixed by the brief (2026-08-17)
Python 3.12, FastAPI + Pydantic v2, Celery + Redis, PostgreSQL 16, MinIO, uv,
Next.js 15, Docker sandboxes.
**Rationale:** every serious binary-analysis library is Python-native or
Python-first (LIEF, pefile, pyelftools, capa, yara-python, binwalk, angr,
pyghidra). Rewriting that ecosystem elsewhere is the single biggest way to fail
this project.
**Rejected:** Go/Rust backend — would mean shelling out to Python for every
analyzer, losing type safety at exactly the boundary that matters.

### ADR-0002 — Sandbox interface before any analyzer (2026-08-17)
`SandboxDriver` was written and tested before a single analyzer existed.
**Rationale:** every analyzer will depend on this boundary, and retrofitting an
abstraction under N analyzers means rewriting all N. Podman (rootless, required
by many enterprises) and gVisor must drop in without touching analyzer code.
**Alternatives rejected:** calling docker-py directly from analyzers, "we'll
abstract it later".

### ADR-0003 — The driver removes containers; Docker `--rm` is never used (2026-08-17)
`SandboxSpec.auto_remove` means *the driver* removes the container after
collecting output. The Docker `AutoRemove` flag is explicitly set to `False`.
**Rationale:** `--rm` races log collection — the daemon can reap the container
before we read its output, producing an empty analyzer result with no error.
The reaper covers what a crash leaks.
**Rejected:** `--rm` plus a log-streaming attach, which is more moving parts
for the same guarantee.

### ADR-0004 — Seccomp is an allowlist, applied via inlined JSON (2026-08-17)
`sandbox/profiles/analyzer.json` denies by default (EPERM) and names the
permitted syscalls. The driver reads the file and passes its *contents* in
`security_opt`.
**Rationale:** a denylist silently admits every syscall a future kernel adds.
And the Docker CLI reads profile files client-side while the API expects the
JSON contents — passing a path through the API yields no profile at all, with
no error, which is the worst possible failure for a security control.
Socket syscalls are permitted because network isolation is enforced by the
netns and blocking them breaks libc and the JVM for no gain. `clone3` returns
ENOSYS rather than EPERM so glibc falls back to `clone`.
**Follow-up:** the profile is validated against every new analyzer image; Ghidra
and Wine are the likely sources of surprises.

### ADR-0005 — Tmpfs mounts carry explicit uid/gid/mode (2026-08-17)
Scratch tmpfs mounts specify `uid=10001,gid=10001,mode=0770`.
**Rationale:** found by the M0 acceptance check on its first run. A tmpfs masks
whatever the image did to the underlying directory and is created root-owned
0755, so an image that carefully chowns `/work` still yields a scratch
directory the analyzer cannot write to. It presents as a broken analyzer rather
than a broken mount, which is a bad afternoon.
**Rejected:** `mode=1777` — world-writable buys nothing in a single-user
container and reads badly in an audit.

### ADR-0006 — Windows is a first-class development environment (2026-08-17)
`make.ps1` mirrors every Makefile target.
**Rationale:** most artifacts BARE analyses are Windows binaries, so a
Windows dev box is not an afterthought, and GNU make is not present by default
there. The Makefile stays canonical for CI and Linux.
**Cost:** two files to keep in sync; every new target needs an entry in both.

### ADR-0007 — Run root is mounted at the same absolute path on host and worker (2026-08-17)
*(Superseded by ADR-0009.)*
`${BARE_RUN_ROOT}:${BARE_RUN_ROOT}` rather than a named volume.
**Rationale:** the worker spawns analyzer containers as *siblings* through the
host Docker socket, and the daemon resolves their bind mounts on the host. A
path that exists only inside the worker yields analyzers with empty input
directories and no error at all.
**Rejected:** running the daemon inside the worker (docker-in-docker) — needs
`--privileged`, which is a far worse trade than a documented socket mount.

### ADR-0008 — Degraded analyzers return results; they do not raise (2026-08-17)
`SandboxDriver.run()` returns a `SandboxResult` with a degraded status for
timeouts, OOMs, and start failures. It raises only for an invalid spec, which
is programmer error.
**Rationale:** Ghidra will hang and OOM on real artifacts. That must cost one
degraded analyzer, not the user's whole scan. The report says which analyzers
degraded rather than silently reporting "no findings".

### ADR-0009 — The driver translates host paths; it does not require identical mounts (2026-08-17)
*Supersedes ADR-0007.* The driver holds two views of the run root — `run_root`
(as the orchestrator sees it) and `host_run_root` (as the daemon sees it) — and
rewrites bind sources between them.
**Rationale:** the same-path approach in ADR-0007 is impossible on Windows,
where a host path is `C:\...` and cannot also be a container path. Docker
rejects it outright with "too many colons". Translation is more general and
removes the footgun rather than documenting around it.
**Rejected:** a named volume, which has no host path the daemon can be given.

### ADR-0010 — Findings use a composite primary key (id, run_id) (2026-08-17)
`Finding.id` stays content-derived and excludes `run_id`; the table's primary
key is the pair.
**Rationale:** content-derived IDs are what make "what is new since the last
release" a set difference rather than a fuzzy match, so the same secret must
carry the same id in every release that ships it. That means re-scanning an
artifact legitimately produces the same id again — a different row, same
finding. With `id` alone as the primary key the second scan of any artifact
dies on a unique violation. Finding routes became run-scoped as a consequence,
which is more correct REST anyway.
**Rejected:** hashing `run_id` into the id, which would destroy cross-run
comparability; a surrogate key with a separate `fingerprint` column, which
leaves the user-visible id meaningless.

### ADR-0011 — The detection engine has no heavy dependencies (2026-08-17)
`core/rules/` imports only PyYAML and the standard library. `Severity` lives in
a dependency-free `core/vocab.py`, and `core/__init__.py` is empty of imports.
**Rationale:** the static analyzer image shares `core.rules` with the host, so
the scanner that produces findings in production is the exact source the unit
tests exercise — not a reimplementation that drifts. That only works if the
import does not drag SQLAlchemy and Pydantic into a sandboxed container.
**Cost:** one extra module and a re-export; worth it to keep the analyzer image
at one third-party package.

### ADR-0012 — Triage cannot dismiss a finding at or above high severity (2026-08-17)
A model verdict of `false_positive` on a `critical` or `high` finding sets
status to `needs_review`, not `false_positive`.
**Rationale:** demonstrated in the first live run — the model called a shipped
private key a false positive, reasoning from a marker in the surrounding text.
A model is allowed to be wrong; it is not allowed to be wrong in a way that
hides a shipped private key. Below the floor the model is trusted to reduce
noise, which is where the value is anyway.
**Rejected:** trusting verdicts uniformly; requiring human confirmation for
every verdict, which would defeat the purpose of triage.
### ADR-0013 — The dashboard proxies the API at runtime, not via a rewrite (2026-08-17)
Browser calls go through `web/app/api/[...path]/route.ts`, a Route Handler
using `node:http`. `next.config.ts` declares no `rewrites()`.
**Rationale:** two failures, both found only by using the UI. Next resolves
`rewrites()` at *build* time and bakes the result into the routes manifest, so
an image built without `BARE_API_URL` proxies to `localhost:8000`
forever — and since server components read the env at runtime, every page
renders fine and only uploads, triage, and status changes fail with a 500.
Then `fetch` proved unusable for the proxy itself: Next patches global fetch
and drops `duplex: "half"`, so a streamed request body fails with a bare
"fetch failed" while the identical stream works through plain Node.
`node:http` also pipes uploads instead of buffering them, so a 2 GB installer
never has to fit in the dashboard's memory.
**Rejected:** passing the API URL as a build arg (couples the image to one
deployment topology); calling the API cross-origin with CORS (a findings page
is a list of a company's exposed secrets).

### ADR-0014 — Durations are measured with a monotonic clock (2026-08-17)
`SandboxResult.duration_s` is a stored field fed by `time.monotonic()`, not
`finished_at - started_at`.
**Rationale:** observed in a real run — Docker Desktop's VM corrected its clock
mid-scan and a completed stage reported **-42.4 seconds**. Wall clock jumps
backwards on NTP correction and VM suspend/resume. The timestamps remain for
display and audit; the number a human reads comes from a clock that only moves
forward.

### ADR-0015 — The release gate is a product surface, not a script (2026-08-18)
`core/policy/` is a dependency-light engine (stdlib + PyYAML), `bare
scan` is the CI entry point, and the verdict has four distinct exit codes:
0 pass, 1 blocked, 2 tool error, 3 inconclusive.
**Rationale:** a scanner that can only be driven by a human uploading a file
catches secrets after the decision to ship has already been made. The gate is
where the product's value is realised, so it gets a real engine with its own
tests rather than a wrapper script around the API. Exit code 2 is kept strictly
apart from 1 because "the scanner was down" and "your installer ships an AWS
key" demand different responses; a tool that returns the same code for both
teaches people to re-run until it goes green.
**Rejected:** a shell wrapper around `curl` and `jq` (no way to test the
decision logic); folding the gate into the API's response to the upload
(couples the decision to the scan, so re-gating under a changed policy would
mean re-scanning a 2 GB installer).

### ADR-0016 — The gate fails on what the build introduced, not what it inherited (2026-08-18)
`baseline.mode: new_only` is the default. Findings present in the previous run
of a same-named artifact are reported and counted but do not block.
**Rationale:** this is the difference between a gate a team turns on and a gate
a team turns off. A product with 200 pre-existing findings cannot adopt a tool
that fails every build on day one. It can adopt one that stops the bleeding
today and lets the backlog burn down on a schedule somebody owns. Content-
derived finding IDs (ADR-0010) are what make this a set difference rather than
a fuzzy match, which is exactly the property they were introduced for.
**Cost:** a genuinely bad artifact whose secrets all predate the baseline
passes. Mitigated by reporting inherited findings prominently in every verdict
and by `mode: all` for release branches.
**Rejected:** blocking on everything by default — correct in principle, and the
reason most such gates end up disabled or wrapped in `|| true`.

### ADR-0017 — A model may not open the release gate (2026-08-18)
`trust_llm_dismissals` defaults to false. A finding triage called a false
positive still blocks the release; the gate reopens it.
**Rationale:** ADR-0012's severity floor stops the model dismissing a critical
finding in the database. This is the same principle one layer out, and it has
to be stronger: below that floor the model is trusted to reduce noise for a
human reviewer, but "reduce noise in a queue" and "authorise a release" are
different acts. A human disposition (`accepted_risk`, `fixed`) is trusted,
because a person is accountable for it. Teams that want the model's judgement
to count can opt in per policy.
**Rejected:** honouring triage uniformly, which would make the LLM load-bearing
for a release decision and violate "never require the LLM" in spirit.

### ADR-0018 — An incomplete scan is INCONCLUSIVE, never a pass (2026-08-18)
Degraded stages (timeout, OOM, failure) produce a third verdict with its own
exit code, considered *before* findings are evaluated.
**Rationale:** ADR-0008 made degraded analyzers return results rather than
raise, so a scan finishes with a partial view of the artifact. Reporting that
as "clean" is the failure mode that makes a gate worse than no gate — the
pipeline goes green and everyone believes the artifact was examined. A separate
verdict also stops "we found a problem" and "we could not finish looking" from
collapsing into one red build, which is what teaches people to retry until it
passes.
**Rejected:** treating degradation as a blocking violation (indistinguishable
from a real finding); treating it as a warning (the default nobody reads).

### ADR-0019 — The policy travels to the server; findings do not travel to CI (2026-08-18)
`POST /api/runs/{id}/gate` takes the policy as YAML text and returns a verdict.
The runner never receives the findings list.
**Rationale:** a findings list is a company's exposed secrets in one document.
Shipping it to every build agent would spread it into CI logs, artifact stores,
and whatever retains those — re-leaking exactly what the product exists to
catch (§14). Sending the policy *as the committed bytes* also means one parser
and one set of error messages, instead of a JSON projection that can drift from
the document a reviewer approved. The server additionally holds the baseline,
so "is this new" is a set difference it can answer directly.
**Rejected:** `GET /findings` in CI plus local evaluation (leaks the corpus);
storing policies server-side (takes ownership of "shippable" away from the team
that owns the binary, and loses the git history that is the audit trail).

### ADR-0020 — click is pinned below 8.2 (2026-08-18)
`click==8.1.8` is an explicit direct dependency although only typer uses it.
**Rationale:** click 8.2 changed `Parameter.make_metavar()` to require a `ctx`
argument, which typer 0.15.1 does not pass. The resolver happily picks a newer
click, and the result is that *every* `--help` in the CLI dies with a
`TypeError` while the commands themselves run fine — so it survives a smoke
test and fails the first person who asks the tool what its flags are. Found
while building `bare scan`; it was already broken for `sandbox hello`.
**Follow-up:** remove the pin when typer supports click 8.2+.

### ADR-0021 — Rules carry an explicit exclusion list, not negative lookaheads (2026-08-19)
`Rule.rejects_matching` is a list of regexes; a captured value matching any of
them is dropped in `accepts()`.
**Rationale:** almost every "internal infrastructure" rule needs to say *…but
not the public equivalent*, and the alternative is a negative lookahead
repeated inside each of the rule's patterns, which makes them unreadable and
drifts as patterns are added. Found in the field, not in review: `scm-url`
fired at **high** on `git://github.com/dotnet/runtime` inside a shipped .NET
assembly and on a public GitHub API URL inside a Go binary — both ordinary
build provenance — and blocked two of seven real-world release artifacts. The
rule already declared `https://github.com/example/project` as a negative test,
so its own stated intent was right and only its patterns leaked.
**Rejected:** per-pattern lookaheads (unreadable, repeated); the false-positive
corpus, which is for published literal values (`AKIAIOSFODNN7EXAMPLE`), not for
structural host classes.

### ADR-0022 — The static analyzer parallelises inside one container (2026-08-19)
The scan and the recon extraction run across a `ProcessPoolExecutor` sized from
the container's *cgroup* CPU quota, not the host core count. `sweep` stays in
the parent. `Settings.analyzer_cpus` (default 4) is the quota.
**Rationale:** measured, not assumed. Container spinup is ~0.5s and a scan
spawns exactly two containers (unpack, static), so lifecycle overhead is ~1s
and irrelevant; the cost is rule matching, which is CPU-bound regex work over
independent files. On a 502-file, 64 MB .NET tree in the real sandbox the
production configuration went 35.4s to 13.1s at 4 CPUs and 10.7s at 8, with
byte-identical output. Sizing from `os.cpu_count()` would read 28 on this host
and spawn 28 workers to share a 2-CPU quota, which is slower than one.
**Determinism:** `Executor.map` yields in submission order, so output does not
depend on scheduling (§2.5). Asserted at the unit level and again end to end by
`scripts/bench_analyzer.py`, which fingerprints the whole result document.
**Why `sweep` is not parallelised:** it ranks by rarity *across the corpus* —
the interesting string appears once, `System.Runtime` appears three thousand
times — so per-file sweeps would change its meaning. Only the extraction ahead
of it is split (9.0s to 2.2s across 8 workers).
**Fallback:** a pool that cannot start logs and runs sequentially. Seccomp
profiles, pids limits and a missing /dev/shm all vary by deployment, and a
slower scan beats a lost one — ADR-0008's posture one level down.
**Rejected:** a container per extracted file (400 starts for one installer);
raising `nano_cpus` without reading the cgroup (workers fight over the quota);
warm container pools (complexity for ~1s on a 13s job).

### ADR-0023 — The API authenticates by default, with two scopes (2026-08-24)
`Settings.auth_required` defaults to true. Tokens are 256-bit random strings
stored only as a SHA-256 hash; scopes are `ci` and `admin`.
**Rationale:** a release gate whose verdict anyone on the network can request,
and whose findings anyone can read, is not a control. Defaulting the check off
means every deployment that never set the variable is open, so the default is
on and a fresh stack bootstraps itself: with no tokens present the API mints one
admin token at startup and prints it once. That is the Jenkins/Grafana trade,
and a better one than a shipped default credential or an opt-in control.
**Why two scopes and not more.** ADR-0019 says findings do not travel to CI.
Without a scope that is a convention the first `curl` breaks — so `ci` may
submit an artifact, poll it, request a verdict and fetch SARIF, and may not read
the findings list, artifact bytes, or run triage. Finer permissions on a
two-actor system (a build agent and a human) are configuration nobody maintains
correctly.
**Why SHA-256 rather than a password KDF:** these are 256-bit random secrets,
not user-chosen passwords. There is no dictionary to slow down; what matters is
that plaintext is never stored, comparison is by indexed hash lookup, and a
database dump yields nothing usable.
**Failure posture:** 401 for an absent, unknown, revoked or expired credential;
403 for a valid one with the wrong scope, because "rotate your token" and "use
the right one" are different instructions. Every rejection is written to the
audit log with the redacted prefix — a burst of them is the first visible sign
of someone probing the gate. Revocation is a flag, never a delete.
**Rejected:** mTLS (correct for a service mesh, far too much operational weight
for a self-hosted, air-gap-capable tool); OAuth/OIDC (an identity provider is
exactly what an air-gapped deployment does not have); a token-minting endpoint
(a privilege-escalation target, and the first token cannot require a token).

---

### ADR-0024 — Schema changes ship as migrations; start-up refuses a stale schema (2026-08-25)
Alembic migrates on start-up, on the application's own connection.
`create_all()` is demoted to tests only, and a failed migration aborts the boot.

**The failure that forced it.** A column was added to `RunManifest`, the stack
was rebuilt, and `create_all()` reported success — it creates missing *tables*
and is structurally blind to a missing *column*. The API then returned 500 on
every run read, and a 213 MB scan died at the manifest write with the artifact
already uploaded, unpacked and scanned. Nothing in the test suite could have
caught it: every test builds its schema from the current models, so the models
and the schema agree by construction. Only a *pre-existing* database disagrees,
and until now nothing ever ran against one.

**Three states, one entry point.** `upgrade_schema()` handles an empty database
(every revision runs), a database created by the old bootstrap (no version
table but real data — stamped at `0001_baseline`, then upgraded), and one
already at head (a no-op). The baseline therefore describes the schema as it
stood *before* Alembic existed, which is why the `components` column is a
separate revision rather than part of it: a baseline containing it could not be
stamped onto the deployments that lack it.

**The migration borrows the application's connection** via
`config.attributes["connection"]` rather than building its own engine from
settings. It guarantees the schema being migrated is the schema the process is
about to query; two independently-resolved URLs can diverge, and the symptom of
migrating the wrong database is silence. The command-line path keeps the
engine-building fallback, because there no application exists to borrow from.

**A failed migration is fatal.** The previous bootstrap logged a warning and
served anyway, which is how a missing column became a 500 on an ordinary
request instead of a refusal to start. A process that cannot reach the schema
its code requires has nothing useful to do.

**Portability is enforced, not hoped for.** Autogenerate froze
`server_default` as the Postgres literal `now()`, which is a syntax error in
SQLite; it is written as `sa.func.now()` so each dialect renders its own. The
unit suite migrates SQLite for this reason — it needs no Docker and it is the
only cheap check that a revision is not silently Postgres-only.

**Rejected:** keeping `create_all()` and hand-writing `ALTER`s (what was
already happening, informally, and it is how the live database ended up in a
state no fresh deployment would reproduce); migrating from an entrypoint script
rather than in-process (a second place the database URL is resolved, and it
skips the adoption logic); a migration container as a compose dependency
(correct for Kubernetes, more moving parts than a self-hosted stack needs).

---

### ADR-0025 — A run is claimed with a conditional UPDATE, committed immediately (2026-08-25)
The `queued` → `running` transition is `UPDATE runs SET status='running' WHERE
id=? AND status='queued'`, committed before the scan begins rather than flushed
into the scan's transaction.

**Observed, not theorised.** The whole scan runs inside one transaction, so a
flushed transition is invisible to every other connection until the scan ends.
For a 213 MB installer that is eight minutes during which the run reads as
`queued` — and the orphan sweep requeues a `queued` run after five. It
dispatched a second `scan_run` for a run whose original task was still inside
the static analyzer: two sets of analyzer containers on the same artifact,
racing to write the same rows. The recovery feature caused precisely the harm
it exists to prevent.

**Two defects, two fixes, both needed.** Committing the transition stops the run
*looking* abandoned. The conditional UPDATE stops a duplicate delivery from
being acted on at all — Celery is at-least-once by design, so re-delivery can
happen for reasons that have nothing to do with the sweep, and a read-then-write
claim has a window between the read and the write that two workers can both
pass through.

**A lost claim is not an error.** `scan_run` returns `{"skipped": true}` rather
than failing the task: the worker holding the claim is doing the work, and
failing the duplicate would make a healthy run look broken in the task log.
Nor can a finished run be re-claimed, so a late re-delivery cannot restart a
scan and overwrite completed results.

**Rejected:** a Redis lock (a second system to be correct about, and the
database already has the state); `SELECT ... FOR UPDATE` (holds a row lock for
the whole scan, so an eight-minute transaction blocks the status write); making
the sweep's grace period longer than the longest scan (there is no such number
— it is a function of the artifact).

---

### ADR-0026 — Response models are constructed, not validated from ORM objects (2026-08-25)
Tree-shaped API responses build their nodes field by field. `model_validate` on
a SQLAlchemy object is not used where the schema and the mapper share a field
name that is a relationship.

**The cost was measured.** `ArtifactOut.children` and `Artifact.children` share
a name, so `ArtifactOut.model_validate(artifact)` made Pydantic read the ORM
relationship — lazy-loading that node's entire subtree from the database,
recursively, for every node, and discarding all of it on the next line where
`build()` assigned the real children. 500 nodes took 58 seconds. Constructed
explicitly, the same 500 take under 0.1s. `bare scan` polls that endpoint
every 20 seconds for the duration of a scan.

**Why not `lazy="raise"` on the relationship instead.** It would have turned
this into an exception rather than a slow success, which is better — but it
also forbids the legitimate uses elsewhere in the pipeline, and it makes the
mapper carry a constraint that exists for the benefit of one serialiser.
Constructing the response explicitly puts the decision where the cost is.

**The related cap.** The tree is limited to 500 nodes, ordered by depth so what
survives is the top of the tree and always connected. A recursive installer
unpacks to 68 976 artifacts; no browser renders that, and the exact count stays
in the summary alongside a flag saying the tree was cut.

---

## ADR-0027 — LiteLLM is the transport; the air gap is enforced above it

**Date:** 2026-08-26
**Status:** Accepted

### Context

Provider support was three hand-written adapters (OpenAI-compatible,
Anthropic, Google). Each vendor changes its wire format eventually, and the
list only grows. LiteLLM is maintained, covers well over a hundred providers,
and normalises their errors into typed exceptions.

The objection to adopting it was the air-gap guarantee. `EgressPolicyGuard`
runs immediately before every HTTP call, and `is_local` — derived from the
resolved URL — is what the redaction layer keys off to decide whether
plaintext could ever be sent. Putting a library between this process and the
socket appeared to give that up.

Two mechanisms were tested for intercepting LiteLLM's egress. Both failed:

* Setting `litellm.client_session` to an `httpx.Client` with a request event
  hook catches the OpenAI family and nothing else. Anthropic, Gemini, and Groq
  route through their own HTTP handlers and never touch it.
* Passing an explicit `api_base` is honoured by Anthropic and **silently
  ignored by Gemini**.

Either would have looked like enforcement in review while permitting egress
from a deployment configured to forbid it.

### Decision

Adopt LiteLLM as the transport for every provider except local Ollama, and
enforce the egress policy **at provider construction and at config load**
rather than at the HTTP call.

* `build_provider` refuses to construct a non-local provider when the policy
  denies egress, so no request exists for LiteLLM to route.
* `load_config` applies the same check to every provider in the file, so a
  deployment fails at start-up rather than mid-scan.
* Locality is taken from the base URL when there is one, so a config asserting
  `is_local: true` for a public host is still refused. With no URL — most
  LiteLLM providers have none, because the model prefix is what routes — it
  falls back to the catalog's declaration, defaulting to hosted.
* `EgressPolicyGuard.check_remote_allowed()` exists for the case where the
  destination is not knowable. Under a deny policy, "I cannot tell you where
  this goes" is refused.

Local Ollama keeps its own adapter. LiteLLM speaks Ollama, but the native
adapter has `warm()` — a cold 9 GB model takes 20+ seconds to page in, and
without an explicit warm-up that cost lands on the first candidate and reads as
a slow model — and a health check that lists pulled models and names the
`ollama pull` command when one is missing.

### Consequences

The guarantee is now coarser and stronger. Coarser because it is per-provider
rather than per-request; stronger because it does not depend on intercepting a
library whose internals vary by vendor. An air-gapped deployment cannot hold a
working hosted provider at all.

The per-request URL check remains where a base URL exists, as defence in depth,
along with `litellm.telemetry = False` and `num_retries = 0`.

The cost is a large dependency in an image that also runs the orchestrator, and
trusting LiteLLM not to contact a host other than the one implied by the model
string. That trust is bounded by the construction-time refusal: under a deny
policy there is no configured provider for it to contact anything on behalf of.

### Alternatives rejected

**Keep the hand-written adapters.** Correct on enforcement, wrong on
maintenance: six vendors was already the ceiling of what was worth tracking by
hand, and the request was explicitly for breadth from a maintained project.

**Route everything through a LiteLLM Proxy instance.** Adds a service to
operate and does not remove the question — it relocates it to the proxy's
configuration, which is further from the code that makes the guarantee.

**Patch LiteLLM's HTTP handlers at import.** Enforcement by monkey-patching a
dependency's internals is enforcement that breaks silently on upgrade, which is
the specific failure mode this decision exists to avoid.

---

## ADR-0028 — Analyzer images are Compose services, built by `docker compose up`

**Date:** 2026-08-27
**Status:** Accepted

### Context

The stack has two kinds of image. Compose ran four of them (the shared backend
image, the dashboard) and knew nothing about the other three — `bare/hello:dev`,
`bare/static:dev`, `bare/unpack:dev` — because those are never run
by Compose. The worker spawns them as siblings through the Docker socket, so
they were built out of band by `make images`.

That split produced a bad failure. A fresh clone following the README's
`docker compose up --build -d` came up entirely healthy: every service passed
its healthcheck, `/readyz` was green, the dashboard's setup wizard minted a
token. The first scan then failed in the worker with `START_FAILED`, because
`bare/static:dev` did not exist. `DockerDriver` goes straight to
`containers.create` and never builds or pulls, and the tags are local-only, so
the daemon's implicit pull went to Docker Hub and found nothing.

The failure surfaced at scan time, not boot time, and named a Docker Hub lookup
rather than a missing build step. `docs/SETUP.md` had the correct sequence
(`make images` before `make dev`); the README quickstart and CLAUDE.md §2 both
claimed a working deployment in two commands that did not include it.

### Decision

Each analyzer image gets a Compose service that builds it and exits:

```yaml
  analyzer-static:
    build: {context: ., dockerfile: sandbox/images/static/Dockerfile}
    image: bare/static:${BARE_ANALYZER_TAG:-dev}
    pull_policy: build
    entrypoint: ["/bin/true"]
    restart: "no"
```

`pull_policy: build` is load-bearing and was missed on the first attempt, which
reproduced the original bug one layer up. Naming the image is what makes the
tag shared with the orchestrator, but `bare/static` also parses as a
Docker Hub reference, and Compose's default policy is to pull an image it does
not find locally. On a fresh machine that is a Docker Hub lookup for a
repository that does not exist: `pull access denied for bare/static`,
and the build that was supposed to happen never runs. The backend and web
services never hit this because they declare no `image:` at all and get
project-scoped names nothing could resolve.

The tag is the variable `core/sandbox/images.py` already resolves at scan time,
so the image Compose builds and the image the worker goes looking for cannot
disagree — the same property `make images` had, kept while the build definition
moved. Compose's `:-` covers unset and empty, which is also where
`analyzer_tag()` lands; it cannot strip, so `make images` normalises
whitespace-only ahead of the call. A whitespace-only tag exported into a bare
`docker compose up` is the one case the two still differ on, and there is no
Compose interpolation that would fix it.

They are not services in any useful sense — the `entrypoint` override exists
purely to stop the image's real ENTRYPOINT, an analyzer, from running. The
mechanism that matters is that Compose builds every image in the project before
it starts any container, so one `docker compose up` now produces the analyzer
tags as a side effect of coming up at all.

`worker` additionally declares `service_completed_successfully` on all three.
This is not for ordering, which the build phase already guarantees; it covers
`docker compose up -d worker`, which would otherwise start a worker with
nothing to spawn.

`make images`, `make image-*`, and the CI sandbox job now delegate to
`docker compose build <service>`, so each analyzer's build context, dockerfile
and tag are defined in `docker-compose.yml` and nowhere else. Three copies of a
build invocation was how the `unpack` image came to be missing from
`docs/SETUP.md`'s list in the first place.

Delegating also fixed a live mismatch: `make images` with an exported-but-empty
`BARE_ANALYZER_TAG` built `bare/hello:`, which the daemon rejects
with an error naming nothing useful, while a scan went looking for `:dev`. The
Makefile now normalises the variable the way `analyzer_tag()` does.

### Consequences

The two-command deployment claim is now true from a clean clone. `docker compose ps`
gains three services in `exited (0)`, which reads as noise until you know what
they are — hence the comment block above them in the compose file.

`docker compose up` rebuilds an analyzer image only when it is absent; it does
not notice that `core/rules/` changed. That is the same behaviour as before for
everyone who ran `make images` once, but it now looks like Compose's
responsibility. `make dev` passes `--build`, and CI builds explicitly, so the
paths that need freshness have it.

### Alternatives rejected

**`profiles:` on the analyzer services.** Exactly backwards: a profiled service
is excluded from the default `up`, so its image would not be built either. It
solves the "don't run them" half at the cost of the half that matters.

**`deploy.replicas: 0`.** Would avoid the exited containers, but whether the
build phase still covers a service scaled to zero is an implementation detail of
Compose rather than a documented guarantee. A one-shot `/bin/true` is ugly and
certain; this is elegant and conditional on behaviour nobody promised.

**Have `DockerDriver` build a missing image on demand.** Gives the analyzer
path a build context and a writable Docker socket dependency at scan time, and
turns a deterministic boot-time cost into a first-scan latency spike. The
driver's job is to run a container under a boundary, not to produce images.

**Leave it and fix the documentation.** The correct sequence was already
documented in one place and wrong in two others. A deployment step that is only
discoverable by reading the right file is the failure this removes.

---

## ADR-0029 — The API is the only migrator, and everything else waits for it

**Date:** 2026-08-27
**Status:** Accepted

### Context

`docker compose up` is the whole deployment (ADR-0028 finished the build half of
that). What it produced was a stack that came up in an order nothing enforced.

Only the API migrates: `api/main.py`'s lifespan calls `upgrade_schema()`, and
uvicorn does not serve until the lifespan has finished. Every other service that
reads the database — both worker lanes, beat, and the dashboard — depended on
Postgres being *healthy*, which means Postgres accepts connections, not that it
has any tables. On a cold start they raced the migration.

The race was mostly survivable by luck. A scan can only be submitted through the
API, which is up only after migrating, so the fast lane usually had work only
once the schema existed. Beat's reaper is the exception: it runs on a schedule
from the moment beat starts, and `_active_run_ids()` returning `None` against a
missing `runs` table was already documented as degrading it to age-based
cleanup. That is a race that had been showing up as a known issue rather than as
a startup failure.

Separately, a worker that was running but wedged — a task that never returns, a
dropped broker connection — was visible only by reading logs, carried in
CLAUDE.md §6 as debt. Compose restarts a process that exits; it cannot see one
that stopped making progress.

### Decision

Everything that reads the database waits on `api: condition: service_healthy`.
A passing `/healthz` is exactly the signal wanted, because uvicorn serves only
after the lifespan migration completes — so the edge means "the schema exists",
not merely "a process was launched". `web` moves from `service_started` to the
same condition for the same reason.

Both worker lanes get a healthcheck that pings *their own* Celery node:
`python -m core.orchestrator.health`. `celery inspect ping` with no destination
answers for the whole cluster, which would let the fast lane look healthy for as
long as the heavy lane replied.

That check is a Python module rather than a shell one-liner because it has to
name the node, and neither shell route is safe: `$HOSTNAME` is a bash variable
while the healthcheck runs under `sh`, and `hostname(1)` is not guaranteed in a
slim image. The interpreter is guaranteed — it is a Python image.

Beat gets no healthcheck. It answers no `inspect ping`, and the base image has
no `pgrep` to approximate one with. The gap is written into the compose file
instead, and a unit test asserts the explanation is still there.

Every long-lived service also pins `logging` to a rotating json-file driver.
Docker's default never rotates, so a stack left running fills the disk with logs
of its own healthchecks — which these changes make considerably more frequent.

### Consequences

Cold start is slower and correct: workers now wait for the API rather than
starting beside it. A stack whose API cannot become healthy no longer brings up
workers that would have failed on their first database access; it fails visibly
at the API instead.

`docker compose up -d worker` now pulls in Postgres, Redis, MinIO and the API,
because that is genuinely what a worker needs to do anything.

The invariant this rests on — that the API is the only migrator — is not
self-enforcing, so a test asserts it by scanning the source for other callers of
`upgrade_schema()`. If a second one ever appears, the dependency edges stop
meaning what they say, and that test is what says so.

### Alternatives rejected

**Run migrations in every service's entrypoint.** Concurrent `alembic upgrade`
against one database is a lock convoy at best; Alembic's version table is not a
coordination primitive. It also spreads a schema-write privilege across every
container in the stack.

**A dedicated one-shot `migrate` service everything depends on.** Cleaner in
principle, and worth doing if a second migrator ever appears. Rejected now
because it splits `upgrade_schema()` away from the process whose code the schema
has to match, and the API already refuses to serve a schema older than itself —
moving the migration out would make that guarantee weaker, not stronger.

**`condition: service_started` with retries in the worker.** Trades a startup
guarantee for a runtime one, and puts a retry loop around every database access
rather than at one point where the answer is known.

**A shell healthcheck using `$HOSTNAME` or `hostname(1)`.** Both assume
something about the image that is not true or not guaranteed, and the failure
mode is a healthcheck that reports a healthy worker as unhealthy forever.

---

## ADR-0030 — The packaged LLM config ships inert

**Date:** 2026-08-27
**Status:** Accepted

### Context

`config/llm.yaml` is not a config file in the usual sense. It is the *packaged
default*: `router.ensure_runtime_config()` copies it into the data volume on
first use, and everything afterwards — the setup wizard, the settings page —
writes to that runtime copy. The packaged file is what every deployment
inherits before anyone has configured anything.

It shipped with `enabled: true` and two Ollama providers pointing at a
developer's LAN address. So a clean install of BARE, on any network,
started up believing it had two working models on a machine it had never heard
of. Opening the settings page probed both, and each probe waited out its
timeout — 15 seconds, serially, because the endpoint had no listener to refuse
the connection. The page appeared to hang.

Two independent faults met there. The config leaked one person's network
topology into every clone of the repository. And the probe path had no bound
worth the name: `OllamaProvider.health()` hard-coded a 15-second timeout with no
way for a caller to shorten it, and both `health_check_all()` and the settings
endpoint looped over providers one at a time.

### Decision

The packaged config ships `enabled: false`, with no `providers:` and no
`roles:`. The commentary that explains the routing — the measured throughput
numbers, why `discover` and `investigate` go to the fast model — stays, because
it is the reasoning behind what the wizard picks and is worth reading. The
concrete values become commented examples against `localhost`.

Nothing is lost operationally: the setup wizard writes `enabled: true`, the
provider, and every role when an operator adds one, and `_validate` skips a
disabled config entirely, so roles naming providers that no longer exist cannot
break the load.

Probing gets a bound and gets parallelised. `health()` takes a `timeout_s`
defaulting to `HEALTH_TIMEOUT_S = 5.0` — a health probe is a UI interaction, not
a scan, and a reachable endpoint answers in milliseconds, so a long timeout only
buys a longer stare at a spinner. `health_check_all()` runs the probes on a
thread pool, and the settings endpoint calls it rather than keeping a second,
serial copy of the same loop.

The dashboard gets `app/settings/loading.tsx`. The page is a dynamic server
component that awaits every probe before it renders, so even a bounded wait
showed the browser nothing at all.

### Consequences

A fresh deployment now has no model configured and says so, which is the honest
state and matches the `--no-llm` default the pipeline is built around (§2.5).
The cost is one extra step for an operator who previously inherited a working
config by accident — but that config only worked on one LAN.

Worst-case settings latency drops from the sum of every provider's 15-second
timeout to roughly one 5-second timeout, behind a skeleton rather than a blank
page.

Shortening the health timeout to 5s could in principle mark a genuinely slow but
working provider unhealthy. A `/api/tags` call that takes longer than five
seconds is a provider that will not survive a triage pass over thousands of
candidates, so reporting it is closer to right than hiding it.

**The address remains in git history.** Four commits on `main` contain it,
back to `b144f54`. Stripping the working tree does not remove them, and
rewriting published history is not something to do as a side effect of a bug
fix. It is an RFC1918 address, which bounds the disclosure to network topology
rather than anything reachable — but the decision to rewrite or leave it is the
repository owner's.

### Alternatives rejected

**Gitignore `config/llm.yaml`.** It is `COPY`'d into the backend image and is
the seed for every runtime config; an absent file means `ensure_runtime_config`
seeds nothing and the shipped commentary disappears. The file is not the
problem — its contents were.

**Keep the providers but point them at `localhost`.** Still ships
`enabled: true`, so a fresh install still probes on page load and still reports
two unhealthy providers nobody asked for. Inert beats plausible-but-wrong.

**Cache the probe results.** The page's own text says a stale green tick is
worse than none, and that is right: "test connection" is the question being
asked. Making the probe fast is the fix; making it rare is an evasion.
