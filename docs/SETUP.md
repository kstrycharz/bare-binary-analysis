# Setup and first scan

A complete walkthrough from an empty machine to a scanned artifact with AI
triage. Roughly 20 minutes, most of it waiting on image builds.

Everything here has been run end to end on Windows 11 with Docker Desktop and
an Ollama host on the LAN. Linux and macOS differ only in the `make` invocation.

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Get the code and configure](#2-get-the-code-and-configure)
3. [Build the images](#3-build-the-images)
4. [Start the stack](#4-start-the-stack)
5. [Verify the sandbox](#5-verify-the-sandbox)
6. [Run your first scan](#6-run-your-first-scan)
7. [Set up your model](#7-set-up-your-model)
8. [Reading the dashboard](#8-reading-the-dashboard)
9. [Scanning your own artifact](#9-scanning-your-own-artifact)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| **Docker** (Desktop or Engine) | Every analyzer runs in a disposable container | `docker --version` |
| **[uv](https://docs.astral.sh/uv/)** | Python dependency resolution | `uv --version` |
| **Node 22+** | Builds the dashboard | `node --version` |
| ~8 GB free disk | Images, Postgres, MinIO | |

**Optional:** an [Ollama](https://ollama.com) host for AI triage. Everything
works without one — see [§7](#7-set-up-your-model).

Windows users: Docker Desktop must be in **Linux containers** mode (the
default). GNU `make` is not required; use `./make.ps1 <target>` instead, which
mirrors every Makefile target.

---

## 2. Get the code and configure

```bash
git clone <your-remote> bare && cd bare
```

```bash
cp .env.example .env
```

Now open `.env` and set **one** variable. This is the only setting that
commonly goes wrong, so it is worth understanding rather than pasting:

```bash
BARE_RUN_ROOT_HOST=/var/lib/bare/runs
```

On Windows use a Windows path:

```bash
BARE_RUN_ROOT_HOST=C:\bare\runs
```

**Why this exists.** The worker spawns each analyzer as a *sibling* container
through the host's Docker socket. When it asks the daemon to bind-mount a
directory, the daemon resolves that path **on the host**, not inside the
worker. So there are two views of one directory: `BARE_RUN_ROOT_HOST`
(what the daemon sees) and `/var/lib/bare/runs` (what the worker sees).
The driver translates between them.

Get it wrong and analyzers receive empty input directories with no error at
all — the scan "succeeds" and finds nothing. That failure is silent, which is
why this is step two rather than a footnote.

Create the directory:

```bash
mkdir -p /var/lib/bare/runs
```

Install Python dependencies:

```bash
make install
```

<details>
<summary>Windows</summary>

```powershell
New-Item -ItemType Directory -Force -Path C:\bare\runs
./make.ps1 install
```
</details>

---

## 3. Build the images

```bash
make images
```

This builds three analyzer images:

- `bare/hello:dev` — the reference analyzer and isolation probe
- `bare/static:dev` — string extraction, rule matching, entropy, file ID
- `bare/unpack:dev` — recursive unpacking of nested containers

You can skip this step: they are Compose services (ADR-0028), so `make dev`
below builds them along with everything else. Run it on its own when you want
the build cost paid up front, or to rebuild one analyzer in isolation with
`make image-static`.

All are built from a digest-pinned Python base. The static analyzer installs
exactly one third-party package (PyYAML); a sandboxed scanner has no business
carrying an ORM.

First build takes a few minutes. Subsequent builds are cached.

### Tagging the images

`dev` is the default and needs no configuration. For anything you deploy rather
than develop against, set a real tag — `BARE_ANALYZER_TAG` is read by both
the build and the orchestrator that runs the containers, so the two cannot
disagree about which image they mean.

```bash
# Local development (default) — builds and runs :dev
make images

# Production / remote box
export BARE_ANALYZER_TAG=latest   # or 0.1.0, or a git sha
make images
docker compose up -d
```

<details>
<summary>Windows</summary>

```powershell
$env:BARE_ANALYZER_TAG = 'latest'
./make.ps1 images
docker compose up -d
```
</details>

Put it in `.env` to make it stick for `docker compose`, the same way the run
root is set.

For a single analyzer — pinning a digest, or pulling one image from a different
registry — `BARE_STATIC_IMAGE`, `BARE_UNPACK_IMAGE`, and
`BARE_HELLO_IMAGE` take a complete reference and win over the tag:

```bash
export BARE_STATIC_IMAGE=registry.internal/bare/static@sha256:...
```

---

## 4. Start the stack

```bash
make dev
```

That brings up eight services: Postgres, Redis, MinIO, the API, two Celery
worker lanes, the beat scheduler, and the Next.js dashboard. Wait for the API
to report healthy — about 40 seconds on a cold start.

Check it:

```bash
curl -s http://localhost:8000/readyz
```

You want `"ready": true`. The `advisory.sandbox` entry reporting unhealthy is
**correct** — the API deliberately has no Docker socket, because spawning
containers is the worker's job. It is reported but does not gate readiness.

Open <http://localhost:3000>. The API requires a bearer token by default
(`BARE_AUTH_REQUIRED=true`), and a fresh deployment has none yet — the
dashboard notices and opens a one-time setup wizard instead of the runs list.
Click through it: it mints the first admin token and saves it for the
dashboard's own use immediately, no `.env` edit or restart required. A
headless operator gets the same mint via
`curl -X POST http://localhost:8000/api/setup/bootstrap`. After that, or on
any later visit, you land on the (empty) runs list.

---

## 5. Verify the sandbox

Before scanning anything real, confirm the isolation boundary actually holds:

```bash
make sandbox-check
```

```
isolation probe (observed from inside the container):
  uid/gid: 10001:10001
  ok   write_rootfs: expected blocked, got OSError
  ok   write_input: expected blocked, got OSError
  ok   tcp_connect: expected blocked, got OSError
  ok   dns_resolve: expected blocked, got gaierror
  ok   unshare_userns: expected blocked, got PermissionError
  ok   ptrace_self: expected blocked, got PermissionError
  ok   write_work_tmpfs: expected allowed, got succeeded
  ok   write_output: expected allowed, got succeeded
```

These results are reported by the analyzer **from inside its own container**,
not read off the daemon's configuration. That distinction matters: passing a
seccomp profile *path* through the Docker API silently applies no profile at
all, and a test that only inspected the container's declared config would
happily pass against a boundary that was not there. The `unshare` and `ptrace`
lines are the ones that prove the profile actually loaded.

Any `FAIL` here means stop and investigate before submitting real artifacts.

---

## 6. Run your first scan

Build the synthetic corpus — small binaries with deliberately planted,
cryptographically invalid credentials:

```bash
make corpus
```

Then run the end-to-end demo:

```bash
uv run python scripts/demo.py
```

You should see something like:

```
2. Scan  (sandboxed container, no network)
   static     completed  0.34s  10 evidence rows

3. Findings  9 deterministic
   critical AWS access key ID              AKIA••••••••••••9E1F      0x33e ascii
   critical GitHub token                   ghp_••••••••••••S7uI      0x5b9 utf-16le
   critical Private key in PEM format      ----••••••••••••----      0x7af ascii
   high     Database connection string     jdbc••••••••••••ater      0x40d ascii
   medium   PDB path leaking internal ...  C:\b••••••••••••.pdb      0x677 utf-16le

   3 of these are UTF-16LE only — a scanner that reads
   ASCII strings alone would have missed them entirely.
```

That last line is the point of the product. Windows binaries keep a large share
of their strings as wide characters, and a scanner that only walks ASCII misses
roughly half the secrets in a typical `.exe`.

Note also what is **not** in the list: the corpus deliberately contains
`AKIAIOSFODNN7EXAMPLE` and `127.0.0.1`. Those are in the false-positive corpus
and never became findings. A scanner whose first result is the AWS
documentation example is one people mute by week two.

---

## 7. Set up your model

**You can skip this entirely.** The pipeline is deterministic-first: every
finding above came from a rule, with no model involved. Triage classifies and
explains findings; it never creates them.

### Choosing a model

Triage runs over *every candidate* — thousands for a large installer — so it
needs a small, fast, **non-reasoning** model. Explanation runs over the handful
of confirmed findings, where quality matters and volume does not. That is what
role routing in `config/llm.yaml` is for.

Measured on a DGX Spark (GB10, 128 GB unified memory, ~273 GB/s):

| Model | Size | Per candidate (warm) | Suitable for |
| --- | --- | --- | --- |
| `qwen2.5-coder:14b-instruct-q4_K_M` | 9 GB | **2.2 s** | triage ✅ |
| `qwen2.5-coder:7b-instruct-q4_K_M` | 4.4 GB | 2.1 s | triage |
| `glm-4.7-flash:bf16` | 55.8 GB | 25–48 s | explain, summarize |

Two results worth understanding:

**The 14b is the same wall-clock as the 7b.** At ~32-token outputs the time is
dominated by prompt processing and fixed overhead, not generation — so the
larger model is effectively free, and its reasoning is visibly sharper. Use the
14b.

**Large bf16 models are bandwidth-bound, not compute-bound.** A 55.8 GB model
must stream every weight per token, so ~273 GB/s ÷ 55.8 GB ≈ 5 tokens/sec is a
hard ceiling regardless of how much compute the box has. A reasoning model then
spends most of those tokens deliberating *before* it answers. Excellent for 20
explanations; unusable for 5,000 triages.

### Pull and configure

```bash
ollama pull qwen2.5-coder:14b-instruct-q4_K_M
```

The dashboard's Settings page is the shortest route: it probes the endpoint
before saving, and it writes the runtime config for you.

By hand, edit the **runtime** config — `data/llm.yaml` in the backend data
volume, not `config/llm.yaml`. The latter is the packaged default that seeds it
on first use, and it ships disabled and empty on purpose so that no deployment
starts out reaching for a host somebody else configured:

```yaml
enabled: true

roles:
  triage: local-fast
  explain: local-reasoning

providers:
  local-fast:
    kind: ollama
    base_url: http://10.0.0.5:11434   # ← your Ollama host
    model: qwen2.5-coder:14b-instruct-q4_K_M
    num_ctx: 8192

policy:
  egress: deny
  redaction: strict
```

`egress: deny` still permits loopback and private addresses — an Ollama or vLLM
box on your own LAN is not egress in any sense a security team cares about.
Cloud providers are blocked under this setting and fail at config load, not
mid-scan.

Three things to know when the provider lives on another machine, not this one:

- **Use the IP, not a bare hostname.** The guard classifies the URL's literal
  host — `http://192.168.1.50:8000` and `http://vllm-box.local:8000` (mDNS) are
  recognised as local; `http://vllm-box:8000` is **blocked** under `deny`,
  because proving a plain hostname resolves to a private address would mean
  trusting DNS, and "cannot tell" under a deny policy means refuse.
  `policy.allowed_hosts` narrows an `allow` policy; it cannot widen a `deny`
  one. If you must use a hostname, that is `BARE_EGRESS_POLICY=allow` plus
  `allowed_hosts: [vllm-box]` to keep everything else refused.
- **Reserve the lease.** A static IP or DHCP reservation on the model box: if
  its address changes to a different device on the subnet, BARE still treats it
  as local, because that is what the address says.
- **The probe runs inside a container**, not on your workstation. Docker
  Desktop reaches host-LAN IPs through the VM's NAT in almost all cases; when a
  provider shows *unreachable* in the UI but `curl` from Windows works, check
  from the container:

  ```bash
  docker compose exec api python -c "import httpx; print(httpx.get('http://192.168.1.50:8000/v1/models', timeout=5).status_code)"
  ```

Verify from inside the worker, which is what actually makes the calls:

```bash
docker compose restart worker
docker compose exec worker python -c "
from core.llm import load_config, health_check_all
for n, h in health_check_all(load_config()).items():
    print(n, h.healthy, h.detail)"
```

Or just open <http://localhost:3000/settings>, which probes every provider live.

### Run triage

```bash
uv run python scripts/demo.py
```

```
4. AI triage  (advisory; findings above are unchanged)
   qwen2.5-coder:14b-instruct-q4_K_M: 9 triaged in 21.4s
   — 7 confirmed, 2 dismissed, 0 need review
```

### The guardrail, demonstrated

In our run the model called the **shipped private key** a false positive. It had
a plausible reason — the synthetic corpus embeds a "THIS IS SYNTHETIC TEST DATA"
marker — but on a real artifact that would be wrong in the most expensive
possible direction.

Here is what BARE did with that verdict:

| Finding | Severity | AI verdict | Actual status |
| --- | --- | --- | --- |
| Private key in PEM format | critical | false_positive | **needs_review** |
| PDB path leaking directory | medium | false_positive | false_positive |

Findings at `high` or above are **never auto-dismissed** on a model's say-so.
They are demoted to `needs_review` so a human still sees them. Below that
floor, the model is trusted to reduce noise.

A model is allowed to be wrong. It is not allowed to be wrong in a way that
hides a shipped private key.

---

## 8. Reading the dashboard

Open <http://localhost:3000>.

**Runs** — every scan, newest first, with a severity rollup and a delta column.
The delta answers the question CI actually asks: *what is new since the last
release?* Finding IDs are derived from content, so that comparison is a set
difference rather than a fuzzy match.

**Run detail** — live per-analyzer progress over SSE while scanning, then the
stage table, the run manifest, and the findings explorer.

The **run manifest** is worth a look. It records the artifact hash, rule-pack
version and hash, analyzer image *digests* (not tags), and tool versions. Two
runs with the same fingerprint must produce identical findings.

**Findings explorer** — expand any finding for its offsets, encoding, entropy,
masked value, context, and remediation. Filter by severity, or show only what
is new.

The **"Deterministic view only"** toggle is the control that matters. Switch it
on and every AI-derived field disappears: verdicts, reasoning, model
attribution. What remains is exactly what the scanner produces with no model
configured. You should always be able to answer *"would this finding exist
without the AI?"* — and the honest way to answer it is to look.

**Rules** — the loaded pack, its hash, and every rule with its severity and
description. Rules tagged *high noise* are deliberately over-inclusive; missing
a live key is far worse than surfacing a dud, and triage carries the precision
burden.

---

## 9. Scanning your own artifact

Via the dashboard: **New scan**, choose your file, complete the attestation.

Via the API:

```bash
curl -X POST http://localhost:8000/api/runs \
  -F "file=@./dist/installer.exe" \
  -F "attested_by=you@example.com" \
  -F "attestation_reference=Release gate for RELEASE-4821; we build and ship this" \
  -F "llm_enabled=true"
```

### About the attestation

It is not a checkbox. The reference field is validated, recorded in an
append-only audit log, and printed in every report generated from the scan.
`"yes"` is rejected.

The reason is straightforward: an auditor reading the record in two years needs
to be able to tell what authorised the analysis. If you are scanning a third
party's artifact for due diligence, read [SECURITY.md](../SECURITY.md) first —
whether that is lawful depends on the licence, your jurisdiction, and how you
obtained the file.

### If BARE finds something

**Rotate the credential.** Do not merely remove it from the next build. The
version that already shipped is still out there, and the finding is evidence it
was exposed.

---

## 10. Troubleshooting

### The scan completes but finds nothing in an artifact you know is dirty

Almost always `BARE_RUN_ROOT_HOST`. The analyzer got an empty `/input`.

```bash
docker compose exec worker printenv BARE_RUN_ROOT_HOST
ls -la /var/lib/bare/runs
```

The path must exist **on the host** and match what the worker reports.

### `make dev` fails with "mount denied ... too many colons"

A Windows path is being used where a container path is expected. Ensure you set
`BARE_RUN_ROOT_HOST` (the host path) and not `BARE_RUN_ROOT`.

### Triage says "the LLM layer is disabled in config/llm.yaml"

Either `enabled: false`, or the worker cannot see the file. Check:

```bash
docker compose exec worker cat /app/config/llm.yaml
```

### Triage returns errors like "exhausted its token budget on reasoning"

You have pointed the `triage` role at a reasoning model. It is spending its
whole output budget on the `thinking` stream before answering. Route triage to
a non-reasoning model — see [§7](#7-set-up-your-model).

### Provider health says the model is not pulled

The model name must match exactly, including the quantisation tag:

```bash
curl -s http://YOUR_HOST:11434/api/tags | grep name
```

### The stack starts but the dashboard shows "API unreachable"

```bash
docker compose logs api --tail 50
docker compose ps
```

If Postgres is unhealthy, the API will not be ready. `make clean` then
`make dev` recreates the volumes.

If everything is healthy but every page still says a token is required, the
dashboard hasn't completed setup — open <http://localhost:3000/setup>
directly. It only ever mints once: a 409 there means a token already exists in
Postgres, but the dashboard's own copy of it (persisted in the `web-data`
volume) is missing or stale — most often because only `postgres-data` was
removed by hand rather than the whole stack. Recreate both together:

```bash
docker compose down --volumes
docker compose up --build -d
```

### A worker crash-loops

```bash
docker compose logs worker --tail 50
```

### Everything is broken and you want to start over

```bash
make clean     # stops the stack and deletes volumes — destroys uploaded artifacts
make dev
```

---

## What next

- `make check` — lint, type-check, and the unit suite; no Docker needed
- `make test-integration` — sandbox isolation tests against a real daemon
- [CLAUDE.md](../CLAUDE.md) — current status, architecture decision log, roadmap
- [ARCHITECTURE.md](../ARCHITECTURE.md) — how the pipeline fits together
- [THREAT_MODEL.md](../THREAT_MODEL.md) — what the sandbox defends against, and what it does not

Recursive unpacking (installers → archives → configs), Ghidra cross-references,
PDF and SARIF reports, and the cloud LLM adapters are the next milestones.
