# Containers

What each container in a BARE deployment does, what it talks to, what happens
when it dies, and which of them could hurt you.

`docker compose up` starts eight long-lived services, runs four to completion
and stops, and builds five images. If you have ever wondered why there are two
workers, or why four "services" show as `exited (0)` immediately, this is the
file.

[ARCHITECTURE.md](../ARCHITECTURE.md) covers the pipeline and the sandbox
design. This covers the runtime: the operational view.

---

## Two kinds of container

The distinction that explains most of the confusion:

**Long-lived services.** The stack — database, broker, object store, API,
workers, scheduler, dashboard. Started by Compose, restarted on failure, alive
until you stop them.

**Ephemeral analyzer containers.** One per analyzer per artifact, created by the
worker through the Docker socket, killed and removed when the analysis finishes.
Compose never sees them. They are the containers that actually touch your
binary, and they are the most locked-down thing in the system.

The three `analyzer-*` entries in `docker-compose.yml` are neither. They exist
only to **build** the analyzer images so that one `docker compose up` produces
everything (ADR-0028). Each builds an image, runs `/bin/true`, and exits 0. Seeing
them as `exited (0)` in `docker compose ps -a` is success, not failure — and they
do not appear in plain `docker compose ps` at all, because it hides stopped
containers.

---

## At a glance

| Container | Kind | Image | Restarts | Healthcheck | Privileged? |
| --- | --- | --- | --- | --- | --- |
| `postgres` | service | `postgres:16-alpine` | unless-stopped | `pg_isready` | no |
| `redis` | service | `redis:7-alpine` | unless-stopped | `redis-cli ping` | no |
| `minio` | service | `minio/minio` (pinned) | unless-stopped | `mc ready local` | no |
| `minio-init` | one-shot | `minio/mc` (pinned) | no | — | no |
| `api` | service | built, `deploy/Dockerfile.backend` | unless-stopped | `GET /healthz` | root in container, **no Docker socket** |
| `worker` | service | built, same image as `api` | unless-stopped | Celery ping to its own node | **Docker socket — root-equivalent on the host** |
| `worker-heavy` | service | built, same image as `api` | unless-stopped | Celery ping to its own node | **Docker socket — root-equivalent on the host** |
| `beat` | service | built, same image as `api` | unless-stopped | heartbeat file age (see below) | root in container, no socket |
| `web` | service | built, `web/Dockerfile` | unless-stopped | none | runs as uid 10002 |
| `analyzer-hello` | build-only | builds `bare/hello:dev` | no | — | no |
| `analyzer-static` | build-only | builds `bare/static:dev` | no | — | no |
| `analyzer-unpack` | build-only | builds `bare/unpack:dev` | no | — | no |
| *analyzer runs* | ephemeral | `bare/*:dev` | n/a | — | **the least privileged thing here** |

Only two ports reach the host: `8000` (API) and `3000` (dashboard). Postgres,
Redis, and MinIO are reachable only from inside the Compose network. The
development overlay (`docker-compose.dev.yml`) publishes them for `psql` and
`redis-cli` access, which is exactly why it must never be used for a real
deployment.

---

## Which containers could hurt you

Worth stating plainly rather than leaving in a comment.

**`worker` and `worker-heavy` mount `/var/run/docker.sock`.** Anything that can
talk to the Docker socket can start a privileged container and own the host.
These two are root-equivalent on the machine running BARE. It is deliberate:
they are the only component that spawns analyzer containers, and doing that
requires the socket. It is also the entire reason analyzers run in hard-isolated
sibling containers rather than as code inside the worker process — the component
holding the dangerous capability never parses your binary.

**`api` does not have the socket**, and that is load-bearing. The component
reachable from the network is not the component that can create containers.

**The backend image runs as root inside its containers** (`api`, `worker`,
`worker-heavy`, `beat`) — no `USER` directive in `deploy/Dockerfile.backend`. For
the workers this is required for the socket and the run-root ownership handling.
For `api` and `beat` it is currently inherited rather than needed.

**The dashboard runs as uid 10002**, non-root.

**Analyzer containers are the most constrained thing in the system**: uid 10001,
no network at all, read-only rootfs, every capability dropped,
`no_new_privileges`, a seccomp allowlist, a pids limit, and tmpfs scratch. See
[THREAT_MODEL.md](../THREAT_MODEL.md).

---

## The services

### `postgres`

Findings, runs, artifacts, stages, manifests, audit log, API tokens.

- **Talks to:** nothing outbound. `api`, `worker`, `worker-heavy` connect to it.
- **State:** `postgres-data` volume. **This is the durable one** — losing it
  loses every scan.
- **Healthcheck:** `pg_isready -U bare -d bare`, every 5s, 20 retries. Proves
  the server accepts connections. It does **not** prove the schema exists —
  that is what the `api` dependency below is for.
- **If it dies:** the API returns 503 from `/readyz`; scans fail rather than
  silently losing findings. Compose restarts it, and it recovers from its volume.

### `redis`

Celery broker and result backend. Also the SSE progress fan-out.

- **State: none, deliberately.** It runs with `--save "" --appendonly no`, so
  persistence is off entirely.
- **Healthcheck:** `redis-cli ping`, every 5s, 20 retries.
- **If it dies:** queued-but-unstarted work is **lost**, because there is
  nothing on disk to recover from. This is a deliberate trade — a scan is cheap
  to re-run and a half-restored queue is not — and it is why `beat` runs a
  `recover-orphaned-runs` sweep: without it, a scan queued during a Redis or
  worker restart would sit at `queued` for ever.

### `minio`

S3-compatible object storage for uploaded artifacts and everything unpacked out
of them. Used rather than a cloud bucket so the stack runs air-gapped.

- **State:** `minio-data` volume. Losing it loses the artifacts; the findings in
  Postgres survive but you cannot re-open the files they point at.
- **Healthcheck:** `mc ready local`, every 5s, 20 retries.
- **Console:** port 9001 inside the network, published only by the dev overlay.

### `minio-init`

One-shot. Creates the `bare-artifacts` bucket, sets it to no anonymous access,
prints `bucket ready`, exits 0.

- **Waits for:** `minio` healthy.
- **If it fails:** uploads fail with a missing-bucket error. Its log is one line
  and says which step failed.
- Idempotent (`mc mb --ignore-existing`), so it re-runs harmlessly on every `up`.

### `api`

FastAPI. Auth, attestation, uploads, run management, findings, reports, SSE
progress, the settings and setup endpoints.

- **Port:** 8000 → host.
- **Talks to:** Postgres, Redis, MinIO. **No Docker socket.**
- **State:** `backend-data` volume at `/app/data`, shared with the workers. Holds
  the runtime LLM config and the provider key store — the things the setup
  wizard writes, which must survive `docker compose build` (ADR-0030).
- **Waits for:** Postgres, Redis, and MinIO all healthy.
- **Healthcheck:** `curl -fsS /healthz`, 10s interval, 20s grace, 10 retries.

  Worth understanding precisely. `/healthz` is **liveness and deliberately
  dependency-free**, so a crash-looping database cannot take the API container
  down with it. `/readyz` is the one that checks Postgres, Redis, and MinIO —
  use that for a load balancer.

  The subtle part: **the API is the only component that migrates the database.**
  `api/main.py`'s lifespan runs `upgrade_schema()`, and uvicorn does not serve
  until the lifespan finishes. So a passing `/healthz` proves the schema is
  current, which is why everything else waits on it (ADR-0029).

- **If it dies:** the dashboard shows errors, uploads fail, and in-flight scans
  keep running — the workers do not need the API to finish a scan.

### `worker`

The fast lane. Celery, concurrency 4, queues `control`, `unpack`, `static`,
`llm`. Unpacking, string scanning, correlation, and the LLM calls.

- **Talks to:** Redis, Postgres, MinIO, **the Docker socket**, and — as the only
  component with egress — the configured model provider.
- **Mounts:**
  - `/var/run/docker.sock` — root-equivalent on the host, see above.
  - `/var/lib/bare/runs` — the run root, bind-mounted **at the same absolute
    path on the host and inside the container**. This is not tidiness: the
    worker asks the daemon to create analyzer containers with bind mounts, and
    the daemon resolves those paths on the *host*. Get it wrong and analyzers
    silently receive empty input directories (ADR-0007).
  - `backend-data` — shared with `api`, so the wizard's model config is visible
    to the process that actually calls the model.
- **Waits for:** Postgres, Redis, and the API healthy, plus all three analyzer
  images built.
- **Healthcheck:** `python -m core.orchestrator.health`, 30s interval, 40s grace.
  It pings **this container's own Celery node** by name. Pinging the cluster
  would let the fast lane look healthy for as long as the heavy lane replied,
  which is the opposite of useful. Implemented in Python rather than a shell
  one-liner because it has to name the node and neither `$HOSTNAME` under `sh`
  nor `hostname(1)` in a slim image is reliable.
- **If it dies:** scans stop progressing. Compose restarts it; `beat`'s orphan
  sweep recovers runs that were mid-flight.

### `worker-heavy`

The slow lane. Celery, **concurrency 1**, queues `ghidra`, `dynamic`.

Identical image, identical mounts, identical healthcheck. The only differences
are the queues and the concurrency, and they are the whole point: Ghidra jobs
are slow, want several GB each, and are the most likely thing in the system to
hang. On a shared queue one wedged Ghidra job starves the string scanners that
produce most of the findings. Concurrency 1 because each job wants the memory.

Its queues have no analyzers behind them yet — Ghidra and dynamic analysis are
M5 — so today it starts, idles, and waits.

### `beat`

The Celery scheduler. Runs two periodic tasks:

- `reap-orphaned-containers` — sweeps analyzer containers the driver did not
  remove.
- `recover-orphaned-runs` — the counterpart to refusing to retry a task lost
  with its worker. Without it, a scan queued during a restart stays at `queued`
  for ever.

- **Waits for:** Redis and the API healthy (its reaper reads the `runs` table).
- **Healthcheck: a heartbeat file.** Beat answers no `celery inspect ping`
  (it is not a worker node), so the scheduler itself signs for being alive:
  `HeartbeatScheduler` touches `/app/data/beat/heartbeat` on every tick — and
  `beat_max_loop_interval` pins the tick to 30 s, so the touch happens even
  when nothing is due. The check (`python -m core.orchestrator.beat_health`)
  fails when the file is older than 4 tick intervals: wedged, not merely idle.
  It reads liveness, not correctness — a ticking beat with a dead broker
  passes and is visible where it belongs, in queued work not arriving
  (ADR-0033).
- **If it dies:** scans still work. Cleanup and orphan recovery stop, so stale
  containers accumulate and a run orphaned by a restart stays stuck.

### `web`

The Next.js dashboard.

- **Port:** 3000 → host.
- **Runs as:** uid 10002.
- **Talks to:** the API only, server-side. Every browser call goes through the
  dashboard's own `/api/*` route handler on its own origin, which is why the
  backend ships no CORS configuration at all — a findings page is a list of a
  company's exposed secrets and should never be reachable cross-origin
  (ADR-0013).
- **State:** `web-data` volume, holding the dashboard's own API token — minted
  by the first-run setup wizard so there is no `.env` to edit.
- **Waits for:** the API healthy, not merely started, so the dashboard cannot
  come up and proxy to an API that is still migrating.
- **Healthcheck: none.** If the API is reachable the dashboard is generally fine;
  its failure mode is a rendered error, not a silent one.

---

## The analyzer containers

The ones that actually read your binary. Created per analyzer per artifact by the
worker, then removed.

| Image | Built from | What it does |
| --- | --- | --- |
| `bare/hello:dev` | `sandbox/images/hello/` | Reference analyzer and isolation probe |
| `bare/static:dev` | `sandbox/images/static/Dockerfile` | Strings, rule matching, entropy, file identification |
| `bare/unpack:dev` | `sandbox/images/unpack/Dockerfile` | Recursive extraction — 7z, squashfs, cab |

Every one obeys the same contract: read from `/input` (read-only), work in
`/work` or `/tmp` (tmpfs), write exactly one JSON document to
`/output/result.json`, exit 0 on success and say why on stderr otherwise, never
touch the network, never expect to be root.

Every one runs with:

- **no network at all** — not a sinkhole, not a bridge; `NetworkMode.NONE`
- **read-only rootfs**, with tmpfs for scratch (explicit uid/gid/mode, because a
  tmpfs mount masks whatever the image chowned — ADR-0005)
- **uid/gid 10001**, never root
- **all capabilities dropped**, `no_new_privileges`
- **a seccomp allowlist**, inlined as JSON rather than passed as a path, because
  passing a path silently applies no profile (ADR-0004)
- **a pids limit** and memory and CPU ceilings
  (`BARE_ANALYZER_MEMORY_GB`, `BARE_ANALYZER_CPUS`)

`SandboxSpec` refuses to construct a spec that weakens any of the first four.
They are not defaults — they are invariants with a validator behind them.

**The images are built, not pulled.** `bare/*:dev` are local-only tags, so the
compose services that build them set `pull_policy: build`; without it Compose
would try Docker Hub, find nothing, and fail with "pull access denied" instead
of building.

**Verify the boundary yourself** rather than trusting this page. `make sandbox-check`
runs the probe and reports what the analyzer observed **from inside its own
container** — not root, read-only rootfs, no TCP, no DNS. Inspecting the daemon's
view of a container's configuration proves only that you asked for something.

---

## Start-up order

```
postgres ─┐
redis ────┼──▶ api ──▶ worker ──▶ (spawns analyzer containers at scan time)
minio ────┘     │        ▲
   └─▶ minio-init│       │
                 ├──▶ worker-heavy
                 ├──▶ beat
                 └──▶ web

analyzer-hello / analyzer-static / analyzer-unpack ──▶ (build, exit 0) ──▶ worker
```

Two things are being enforced, not merely sequenced:

1. **Nothing reads the database before it is migrated.** Only the API migrates,
   and it does not serve until it has, so `api: service_healthy` is the signal
   that the schema exists (ADR-0029).
2. **No worker starts without analyzer images.** Compose builds every image
   before starting any container, so the dependency mostly matters for
   `docker compose up -d worker`, which would otherwise start a worker with
   nothing to spawn.

Cold start is roughly 40 seconds once images are built, most of it the API's
migration and health grace period.

---

## Operating notes

```bash
docker compose ps -a                  # -a, or the build-only services look missing
docker compose logs -f worker         # the lane that runs scans
docker compose logs api | head -50    # migration output lands here at start-up
docker compose restart worker         # safe: beat recovers orphaned runs
docker compose down                   # stop, keep volumes
docker compose down --volumes         # stop and DESTROY every uploaded artifact
```

Common failures and where to look:

| Symptom | Where |
| --- | --- |
| Scans stay `queued` | `worker` — is it healthy? `docker compose ps` |
| Scans fail immediately with a missing image | the `analyzer-*` builds; `docker images \| grep bare/` |
| Analyzers get empty input | `BARE_RUN_ROOT_HOST` — must be an absolute *host* path (ADR-0007) |
| Uploads fail | `minio-init` — did the bucket get created? |
| Dashboard errors on every page | `api` — check `/readyz`, not `/healthz` |
| A scan is slow and you cannot tell if it is stuck | currently hard; see the `scan-progress` bounty |

**Analyzer container logs are not currently retained.** The driver collects
stdout and stderr, uses them for the stage's error message, and drops the rest —
and the container is gone by the time you would want to look. If a scan comes
back degraded and the error string is not enough, there is no deeper log to
read. That is the `analyzer-logs` bounty in
[feature-request.md](../feature-request.md).
