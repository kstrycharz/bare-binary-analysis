# Feature requests

Wanted features, written as **bounties**: each one is scoped tightly enough
that someone can pick it up, build it on a branch, and have it judged on
whether it actually works — not on whether it was assigned.

Nothing here is a commitment to merge. A bounty is an invitation to try, and
"tried and rejected" is a real outcome that should leave behind a note saying
why, so the next person does not re-run the experiment.

---

## How a bounty works

1. **Claim it.** Open an issue titled `bounty: <slug>` (the slug is in the
   heading of each entry below) saying what you intend to do. This is only so
   two people don't build the same thing on the same weekend.
2. **Build it on a branch.** `feat/<slug>`, off `main`. Small, atomic,
   Conventional Commits — the same bar as everything else in this repo
   (`CLAUDE.md` §8).
3. **Push and open a draft PR early.** A half-finished branch that shows the
   approach is more useful than a finished one that took the wrong turn.
4. **Make it tryable.** The PR body says how to *see* it working: the command
   to run, the page to open, the artifact to scan. A reviewer who has to
   reverse-engineer how to exercise a feature usually doesn't.
5. **It gets tried.** Someone runs it against a real artifact, not only the
   test suite.
6. **Accepted, revised, or declined** — and if declined, the PR gets a comment
   saying what was wrong with the approach, and this file gets a line under the
   bounty recording it.

### The bar for "accepted"

Non-negotiable, because they are the bar for every other line of code here:

- `make check` passes — ruff, `mypy --strict` on `core/`, unit tests.
- **Unit tests must not require Docker.** Anything that does is an integration
  test, marked `@pytest.mark.integration`, and skips cleanly when Docker is
  absent.
- **Tests ship in the same commit as the code.** Every non-trivial module.
- **Nothing is silently stubbed.** A placeholder raises `NotImplementedError`
  naming its milestone and gets a row in `CLAUDE.md` §6.
- **Determinism holds.** Explicit sort orders; parallelism must not change
  output. Finding ids stay content-derived.
- **The deterministic spine stays intact.** The LLM layer may suppress, rank,
  explain, or investigate. It may never create a finding or change offsets, and
  `--no-llm` must still produce a complete, useful report.
- **An architectural decision gets an ADR.** Append to `docs/ADR.md` with the
  alternatives you rejected and why. This matters more than it sounds: the ADR
  log is what stops the same rejected idea coming back in six months.

Read `CLAUDE.md` §9 before starting anything. There are product guardrails
there — no offensive capability, no plaintext to remote providers, analyzers get
no network and no Docker socket — that are not up for negotiation in a PR.

### Sizing

| Size | Rough shape |
| --- | --- |
| **S** | One module or one component. An afternoon. |
| **M** | Crosses a boundary — worker to API, API to dashboard. A weekend. |
| **L** | New subsystem, new container, or a schema migration. |

---

## Open bounties

### `analyzer-logs` — keep the logs the scanning containers produce · **S**

Today the container's output is collected and then thrown away.
`DockerDriver._collect_logs()` reads stdout and stderr, caps them at
`_MAX_LOG_BYTES`, and hands them back on the `SandboxResult`. Then they stop:
`RunStage` has an `error` column and nothing else, so what the analyzer actually
printed never reaches the database, the API, or the operator. When a scan comes
back degraded, the only way to find out why is `docker logs` against a container
the driver has already removed — which is to say, there is no way.

**Wanted:** analyzer stdout/stderr retained per stage and readable from the run
page. A `GET /api/runs/{id}/stages/{stage_id}/logs` endpoint and a disclosure
panel next to the stage row would do it.

**Watch out for:**
- Logs from an analyzer are **untrusted output derived from a customer's
  binary**. Render them as text, never as markup, and never let them widen an
  API response into something that can carry an attack.
- They can also contain secrets — the analyzer is looking at a file full of
  them. Whatever redaction policy the run was scanned under has to apply here
  too, or this becomes a hole straight through §9.
- Storage. A 213 MB installer can produce a lot of output. There is already a
  byte cap in the driver; decide deliberately whether the database or object
  storage is the right home, and say so in the PR.

**Done when:** a deliberately failing analyzer run shows its output in the
dashboard, the redaction policy demonstrably applies, and a very chatty analyzer
cannot grow a row without bound.

---

### ~~`container-docs`~~ — document what each container is for · **S** · **DONE**

Delivered as [docs/CONTAINERS.md](docs/CONTAINERS.md).

<details>
<summary>Original bounty</summary>

`docker compose up` starts twelve services and builds five images. What each one
does is currently spread across comments in `docker-compose.yml`, three
Dockerfiles, and `ARCHITECTURE.md`, and the split between the two worker lanes —
which is a real architectural decision about not letting a wedged Ghidra job
starve the string scanners — is explained in a YAML comment.

The services: `postgres`, `redis`, `minio`, `minio-init`, `api`, `worker`,
`worker-heavy`, `beat`, `web`, and the three build-and-exit analyzer services
`analyzer-hello`, `analyzer-static`, `analyzer-unpack` (ADR-0028).

**Wanted:** `docs/CONTAINERS.md` — one section per container: what it does, what
it talks to, what happens if it dies, what its healthcheck actually checks, and
which of them hold privilege. Worth naming plainly that `worker` and
`worker-heavy` mount the Docker socket and are therefore root-equivalent on the
host, and that this is the reason analyzers get their own hard-isolated
containers.

**Done when:** someone who has never seen the repo can read it and correctly
answer "why are there two workers" and "which of these could hurt me".
</details>

---

### `scan-progress` — real progress during the scan phase · **M**

The most-asked-for thing on this list.

There is already live progress: `RunProgress` consumes Server-Sent Events and
advances a bar over five phases — queued, unpack, index, static, report. The bar
deliberately moves on *phase* rather than on a clock, because a bar that crept
forward on a timer would be inventing the one thing the operator came to learn.

The problem is that `static` is where a scan spends nearly all its time, and it
is a single indivisible step. A 213 MB installer unpacks to something like
69,000 files, and for the several minutes it takes to scan them the UI says
"running" and nothing else. There is no way to tell a slow scan from a stuck one.

**Wanted:** progress *within* the static phase — files scanned of total, and
ideally the current file. A widget on the run page, fed by the existing SSE
stream rather than a second channel.

**The hard part is the container boundary.** The static analyzer is a batch job:
it runs, then writes its result to `/output` at the end. It has no network, no
Docker socket, and no database — deliberately, and that is not changing for this.
So progress has to travel out some way that respects the boundary. Two plausible
routes, and part of the bounty is arguing for one:

- The analyzer emits progress lines on **stdout**, which the worker is already
  reading. Cheap, and it composes with the `analyzer-logs` bounty above.
- The analyzer writes a **heartbeat file** into its writable `/output` mount,
  which the worker polls. Survives buffering better; costs a polling loop.

**Watch out for:**
- Total file count is not known until unpack finishes. Before then, honest
  output is a count with no denominator — not a fake percentage.
- The analyzer parallelises across CPUs internally (ADR-0022, `BARE_SCAN_WORKERS`),
  so progress has to be aggregated across workers without becoming a
  contention point.
- Don't let a progress channel become a way for analyzer output to steer the
  orchestrator. Parse it strictly; a malformed line is dropped, not trusted.

**Done when:** scanning a large installer shows a moving file count, a stuck
scan is visibly distinguishable from a slow one, and `--no-llm` batch scans with
no dashboard attached are unaffected.

---

### `ghidra` — Ghidra integration · **L**

The headline M5 feature, and the one that turns string matching into real
binary analysis: cross-references, function identification, and evidence that a
hardcoded credential is actually *reachable* rather than merely present.

Groundwork already exists. There is a `worker-heavy` lane on its own queues
(`ghidra`, `dynamic`) with concurrency 1, precisely so a wedged Ghidra job
cannot starve the fast scanners. `SandboxSpec`, the driver, the watchdog, and the
reaper are all analyzer-agnostic. The pattern for adding an analyzer image is
established by `analyzer-static` and `analyzer-unpack`.

**Expect these to bite:**
- **Seccomp.** The allowlist has only ever been exercised against a slim Python
  image. A JVM will need additions. Add them for this image; do **not** weaken
  the profile globally because one image failed. Reproduce with
  `seccomp_profile=None` first to confirm the profile is the cause.
- **Memory.** Ghidra wants several GB. `BARE_ANALYZER_MEMORY_GB` exists; the
  watchdog already distinguishes OOM from timeout, and that distinction needs to
  stay accurate here.
- **Headless mode and determinism.** Two runs of the same artifact must produce
  the same findings, or the run manifest's reproducibility claim breaks.
- **Time.** This is the analyzer most likely to hang. The watchdog kills
  containers that ignore SIGTERM; make sure a killed Ghidra run degrades the
  stage rather than failing the run (ADR-0008, ADR-0018).

**Suggested first slice**, rather than all of it at once: get the image building
and running through the real driver, producing *one* useful thing — a function
count, or the xrefs to a single string offset that a rule already matched. A
narrow vertical slice that reaches the database is worth more than a broad one
that doesn't.

**Consider taking `analyzer-plugin` first.** Ghidra is the obvious bolt-on
module — a big, slow, JVM-based analyzer that has no business living in the same
image as anything else. If the plugin interface exists, this bounty becomes
"write an image and a manifest" instead of "modify the orchestrator", and the
interface gets designed against a genuinely demanding analyzer rather than
against the three small Python ones that already agree with each other.

---

### `runs-live` — the Runs tab does not show runs that are running · **S**

Start a scan, click **Runs**, and the run you just started is often not there.

The data is not the problem: `GET /api/runs` returns every run newest-first with
no status filter, queued and running included, and the run list already knows how
to render a live row — `run.status === "running" || "queued"` has its own
treatment.

The problem is that the Runs tab is the homepage (`/`), and it is a **server
component with no client-side refresh at all**. It is marked `force-dynamic`, so
it re-renders per request, but nothing re-requests: there is no polling, no SSE,
no `router.refresh()`. Two consequences, and a fix should address both:

- **Sitting on the page shows a frozen list.** A run started from the CLI, from
  CI, or by a colleague never appears, and a running row never advances to
  completed.
- **Navigating back to it can show stale data.** Next's App Router caches RSC
  payloads client-side, so a `<Link>` back to `/` can serve what it rendered
  earlier rather than refetching — which is the most likely reason a run started
  seconds ago is missing.

`RunProgress` on the run detail page already does this properly, over SSE, and is
worth copying rather than reinventing: it advances on observable phase rather than
a clock, and refreshes the server component once on reaching a terminal state.

**Watch out for:** don't poll `GET /api/runs` every second for every open tab —
`_summarise()` runs per row. Either extend the existing SSE stream to carry
run-list events, or poll at a sane interval and only while a run is active.

**Done when:** starting a scan in one tab makes it appear in the Runs tab of
another without a manual reload, and a completing run updates in place.

---

### `analyzer-plugin` — make a bolt-on analyzer a drop-in container · **L**

Adding a new analyzer should be: write a container that honours the contract,
declare it, restart. Today it is an edit to at least five files in the core
repository — `core/sandbox/images.py` (the hardcoded
`ANALYZERS = ("hello", "static", "unpack")`), the pipeline that names images and
invokes them, `docker-compose.yml`, the `Makefile`, and `make.ps1` — which means
nobody outside this repo can add one at all.

The foundations are already right, which is what makes this worth doing rather
than rewriting. `SandboxSpec` and `SandboxDriver` are analyzer-agnostic. The
contract is already explicit and already documented by the reference image: read
from `/input`, work in tmpfs, write one JSON document to `/output/result.json`,
exit non-zero and explain on stderr, expect no network and no root. Celery queues
are already split by analyzer class. Evidence records are already normalised, so
a new analyzer's output joins the existing pipeline without touching the
correlator.

**Wanted:** an analyzer *manifest* — a small declarative file an analyzer ships
(name, image, which queue, which artifact types it wants, resource ceilings,
timeout, whether it is enabled) that the orchestrator discovers rather than
having compiled in. Plus a documented output schema, so a third-party analyzer's
evidence is first-class rather than special-cased.

**Watch out for:**
- **The boundary is not negotiable.** A plugin manifest must not be able to ask
  for network, the Docker socket, root, or a writable rootfs. `SandboxSpec`
  already refuses to construct a spec that weakens those; the manifest loader
  has to refuse just as loudly, and there should be a test that a malicious
  manifest cannot widen the sandbox.
- **A third-party analyzer is untrusted code processing an untrusted artifact.**
  That is fine — it is exactly what the sandbox is for — but its *output* is
  untrusted too, and it lands in the database and the UI.
- **Seccomp is per-image in practice.** The allowlist has only been exercised
  against a slim Python image; a JVM or Wine-based analyzer will need additions.
  The manifest may need to carry a profile reference, without letting a plugin
  simply turn seccomp off.
- Versioning: the run manifest records tool versions for reproducibility, and a
  plugin's version has to land there too or two runs stop being comparable.

**Ghidra is the proving case.** If the plugin interface is right, the `ghidra`
bounty becomes "write a Ghidra analyzer image and a manifest" rather than
"modify the orchestrator". Worth building these two together, in that order:
design the interface against Ghidra's real requirements — several GB of memory,
long runtimes, a JVM — rather than against the three small Python analyzers that
already exist and agree with each other.

---

### `re-view` — a reverse-engineering view, not just findings · **M**

Findings answer "what is wrong with this artifact". They do not answer **"what
is this artifact, and how does it work"** — which is the question an analyst
actually starts with, and often the reason they opened the tool.

Wanted: a separate tab alongside Findings that describes the software rather
than its defects. What it is built with, what it talks to, what it does on
startup, which components it bundles, what capabilities it appears to have.

**A surprising amount of this is already computed and thrown away:**

- **Recon inventory** (`core/rules/recon.py`) sweeps what *kinds* of thing are in
  an artifact — independently of the rule pack, explicitly "never a finding". It
  is stored on `RunManifest.recon` as JSON and **exposed by no endpoint at all**.
  It is the closest thing to a "what is this" summary that already exists.
- **Component inventory** (`core/composition`) — the bundled libraries with
  ecosystems, versions, licences, and where in the unpack tree each was found.
  Reachable today only as a CycloneDX download.
- **The artifact tree** — the full recursive unpack structure, already rendered
  on the run page.

So a first slice is mostly *surfacing*: give recon an endpoint, put it and the
component inventory behind a tab, and the view is already more than nothing
without any new analysis.

Beyond that it wants real analysis, and that is where it meets the two bounties
above: imports and linked libraries, entry points, embedded URLs and endpoints
grouped by host, and — once Ghidra lands — a function-level view and the
cross-references that show whether a hardcoded credential is actually reachable.

**Watch out for:**
- **Do not let this become findings by another name.** Recon is deliberately not
  a finding, and presenting "this binary makes network calls" with severity
  colouring would undo that distinction. It is description, not judgement.
- The LLM layer is a natural fit for narrating "how it works" — and the rule
  that it may never create a finding still holds. A narrative is advisory, has
  to be labelled as model-generated, and must not be required: `--no-llm` still
  has to produce this view from the deterministic inventory.
- §9 applies. Describing how software works is not the same as producing an
  exploit, and this view must not drift toward "how to defeat it".

**Done when:** opening a scanned installer shows, without reading a single
finding, what it is built with, what it bundles, and what it appears to reach
out to.

---

## Also wanted

Smaller or more speculative. Same process.

### `beat-healthcheck` — a liveness check for the scheduler · **S**
Both worker lanes have healthchecks (ADR-0029). `beat` does not, because it
answers no `celery inspect ping` and the base image has no `pgrep`. A wedged
scheduler is currently only visible in logs. Probably a heartbeat file plus a
check that reads its mtime. **Good first bounty** — self-contained, and there is
a worked example to copy in `core/orchestrator/health.py`.

### ~~`waive`~~ — `bare waive <id>` · **S** · **DONE**
Delivered as `bare waive`. Building it turned up the real bug: the gate's text
output printed a 12-character id prefix, and waivers match the full id exactly,
so a waiver copied from a red build never applied. The output now prints the
full id, and `bare waive` refuses a prefix and says why.

CI prints finding ids; turning one into a waiver means hand-editing YAML, which
is where waivers acquire missing owners and absent expiries. Wanted:
`bare waive <id> --reason ... --expires ...` appending a well-formed entry.
Should refuse to write a waiver with no expiry.

### `retention-ttl` — make the plaintext promise true · **M**
`CLAUDE.md` §9 promises that retained plaintext is encrypted at rest, has a TTL,
and is auto-purged. None of the three exists. A run scanned with retention
enabled leaves real secrets in Postgres indefinitely. The UI says so at the point
of choosing, which is not the same as the promise being kept. **This is the most
security-relevant item on this page.**

### `go-strings` — a Go-aware string splitter · **M**
Go binaries store strings in one contiguous blob with no separators, so the
printable-run extractor merges unrelated strings and rules match across the seam
(`…per_page=30reflect:`). It affects every rule on every Go binary and needs a
real splitter driven by Go's string table, not a per-rule patch.

### `run-compare` — diff two runs in the dashboard · **M**
The gate already computes "what did this build introduce" against a baseline
run. That computation exists and is tested; it is just not surfaced anywhere a
human can look. Mostly a UI bounty on top of logic that is already correct.

### ~~`sbom-diff`~~ — what changed between two builds · **S** · **DONE**
Delivered as `bare sbom-diff A B`, where each side is a run id or an SBOM file.
Components match on purl identity without the version, so an upgrade is one
change rather than a removal and an addition; licence changes are reported too,
and a diff against an incomplete inventory says so.

SBOM export is deterministic by design: no clock, no random serial, so two
exports of a run are byte-identical specifically so they can be diffed. Nothing
does the diffing. `bare sbom-diff RUN_A RUN_B` reporting added, removed, and
version-changed components is a small command with an obvious audience.

### `vuln-enrichment` — join the SBOM to advisories · **L**
Components are already identified by Package URL, which is the join key every
advisory database uses. Matching against OSV would turn "what is in this
artifact" into "what is wrong with what is in this artifact". Needs an answer
for air-gapped deployments — an offline database bundle, not a live API call —
which is most of the work and the reason it is an L.

### `github-action` — a real marketplace action · **M**
`docs/CICD.md` calls the CLI directly, which works on every platform and is more
wiring than anyone wants. A native GitHub Action and a GitLab component would cut
the integration to a few lines. The scanning logic already exists; this is
packaging.

### `podman` — rootless container runtime · **L**
`PodmanDriver` raises `NotImplementedError`. Rootless Podman is a hard
requirement for some enterprises, and the `SandboxDriver` interface was designed
for exactly this substitution. The isolation suite is the acceptance test: it
must pass against Podman unchanged, because it measures from inside the
container rather than trusting the daemon's view.

### `artifact-tree-paging` — see past the first 500 nodes · **S**
The run detail response caps the artifact tree at 500 nodes. The count stays
exact and every artifact is still scanned, but there is no way to page through
the rest. Needs its own paginated endpoint.

### `metrics` — Prometheus endpoint · **S**
Self-hosted software gets run by people with a monitoring stack. Queue depth,
scan duration by profile, analyzer failure rate by image, and stage degradation
counts are all already computed and thrown away. Must not leak finding content
into labels.

### `readme-screenshots` — show the product in the README · **S**
The README is ~280 lines of prose and not one image. Someone deciding whether to
run `docker compose up` cannot see what they would get: the run list, the upload
form with its attestation, a run page with findings and the artifact tree, an
explanation or investigation transcript, the setup wizard, and — for the CI
audience — what `bare scan` prints when it blocks a build.

Wanted: screenshots of those views in `docs/images/`, placed in the README where
the prose already describes them, each with real alt text.

**Watch out for:**
- **§9 applies to pictures too.** Every screenshot comes from scanning a synthetic
  fixture built from provably-invalid shapes (`AKIAIOSFODNN7EXAMPLE`), with no
  real hostnames, usernames, or tokens in view — and nothing with plaintext
  retention switched on. gitleaks does not read PNGs, so review is the only check.
- **No model output presented as a finding.** An AI panel in a screenshot is
  labelled as advisory, the same way it is in the product.
- **They will rot.** Prefer a small script (Playwright against the Compose stack
  and a seeded run) that regenerates them, over hand-captured images nobody
  updates after the next UI change.
- Size. Compress them; a README that pulls 20 MB of PNGs is its own problem.

**Done when:** a first-time reader can see the dashboard and a blocked CI run
without installing anything, and the images can be regenerated with one command.

### `dogfood` — scan BARE's own releases · **S**
The README claims BARE is a build-pipeline stage gate. Nothing currently verifies
that claim. Wiring the gate into this repo's own CI on release tags is the
fastest way to find out which parts of `docs/CICD.md` are wrong.

### `remediate` — wire it or drop it · **S**
The `remediate` role is routable, configurable in the settings UI, and nothing
calls it. Either implement it or remove it from `EDITABLE_ROLES`. A configurable
role that does nothing is how the explain/summarize gap started. Deciding counts
as completing this bounty.

---

## Proposing something not on this list

Open an issue describing the problem before the solution. The most useful
proposals here have started from "this is what I could not do", not "this is the
feature I want" — the second one tends to arrive already committed to an
implementation, and the implementation is usually the part worth arguing about.

If it touches the sandbox boundary, the deterministic spine, or what may be sent
to a model, read `THREAT_MODEL.md` and `CLAUDE.md` §9 first and say in the issue
how your idea sits with them.
