# BARE as a release gate

How BARE sits in a build pipeline: the build produces an artifact, the
artifact is scanned, and the scan decides whether the release proceeds.

This document is the integration design and the reference for wiring it up.
For running the platform itself, see [SETUP.md](SETUP.md).

---

## 1. The shape of it

```
  ┌──────────┐     ┌──────────┐     ┌───────────────┐     ┌──────────┐
  │  build   │────▶│  scan    │────▶│  release gate │────▶│ publish  │
  │          │     │          │     │               │     │          │
  │ .exe/.msi│     │ sandbox  │     │ policy verdict│     │ signed & │
  │ produced │     │ analysis │     │  0 / 1 / 3    │     │ shipped  │
  └──────────┘     └──────────┘     └───────┬───────┘     └──────────┘
                                            │
                                    ┌───────┴────────┐
                                    │ blocked (1)    │
                                    │ inconclusive(3)│
                                    │                │
                                    │ → pipeline stops│
                                    │ → SARIF to code │
                                    │   scanning      │
                                    │ → summary on PR │
                                    └────────────────┘
```

One command does the middle two boxes:

```bash
bare scan dist/installer.exe --sarif bare.sarif
```

It uploads, waits, evaluates the policy, writes the reports, and exits with a
code the pipeline reads.

### Exit codes

| Code | Meaning | What a pipeline should do |
| --- | --- | --- |
| `0` | **Pass** — nothing blocking under the policy | Continue to publish |
| `1` | **Blocked** — a policy violation | Stop. This is a real finding |
| `2` | **Error** — could not scan (API down, bad policy, timeout) | Stop, but page the platform team, not the release team |
| `3` | **Inconclusive** — the scan did not complete | Stop. The artifact was not fully examined |

`2` is kept strictly separate from `1` on purpose. "The scanner was down" and
"your installer ships an AWS key" demand different responses, and a tool that
returns the same code for both teaches people to re-run until it goes green.

`3` exists because most scanners do not have it. If the unpacker hits its
budget or an analyzer OOMs, the artifact was not fully examined — reporting
that as a pass is a lie the pipeline will believe.

---

## 2. Two decisions that determine whether this gets adopted

### The gate fails on what the build *introduced*

Default policy is `baseline.mode: new_only`. Only findings absent from the
previous scan of the same artifact can fail the build. Inherited findings are
reported, counted, and visible — they just do not block.

This is the difference between a gate a team turns on and a gate a team turns
off. A product with 200 pre-existing findings cannot adopt a tool that fails
every build on day one; it can adopt one that stops the bleeding today and lets
the backlog burn down on a schedule somebody owns.

Set `mode: all` for a greenfield product or a final release branch, where the
inherited set should be empty anyway.

The comparison is a set difference over content-derived finding ids
(ADR-0010), not fuzzy matching — the same secret carries the same id in every
release that ships it.

### The model cannot open the gate

`trust_llm_dismissals` is `false` by default. If AI triage calls a finding a
false positive, it still blocks the release. The model reduces noise for a
human reviewer; it does not sign off a release.

This is ADR-0012's severity floor applied one layer out. That floor already
stops triage from dismissing a critical finding in the database; this stops a
dismissal at *any* severity from unblocking a release. A team that wants the
model's judgement to count can opt in per policy.

`--no-llm` (the default in CI) produces a complete, valid gate decision.

---

## 3. Setup, once per repository

```bash
bare policy init          # writes .bare/policy.yaml
bare policy validate      # confirms it parses and prints what it enforces
git add .bare/ && git commit -m "chore: add release policy"
```

The policy lives in the repository that produces the artifact, not in the
scanner's configuration. The team that owns the binary owns the definition of
"shippable", and weakening it should require a pull request somebody approves.
The file's git history is the audit trail for that.

### `.bare/policy.yaml`

```yaml
version: 1
name: default

block:
  severity_at_or_above: high     # critical|high|medium|low|info, or `none`
  categories: []                 # always block, whatever the severity
  rules: []                      # always block, by rule id

budgets:                         # ceilings for non-blocking severities; -1 = off
  medium: -1

baseline:
  mode: new_only                 # new_only | all

on_degraded: fail                # fail | warn | pass
trust_llm_dismissals: false

waivers:
  max_ttl_days: 90
  require_owner: true
  require_reason: true
```

### `.bare/waivers.yaml`

```yaml
waivers:
  - finding_id: 3f2a91c4e8b7d05a
    reason: >-
      Vendor SDK sample key inside the bundled redistributable. Confirmed
      inert with the vendor; tracked in SEC-4471 for the 2.5 SDK bump.
    owner: kyle@example.com
    expires: 2026-11-15
```

Every field is required and `expires` has no default. A waiver with no end date
is a permanent hole that outlives the reason it was granted for and the person
who granted it — the loader rejects one rather than defaulting it. An expired
waiver blocks the build *and says so*, which is what brings the decision back
for review while it still matters.


### Re-gating without re-scanning

The verdict is a separate call from the scan (ADR-0015), so a run can be
re-evaluated under a different policy without uploading the artifact again:

```bash
bare gate <run-id> --policy .bare/release-policy.yaml
```

Two uses. A policy fix should not cost a twenty-minute scan of a 2 GB
installer. And "would this stricter policy have blocked last week's release?"
is answerable by pointing this at the run, rather than by argument.

Exit codes are identical to `scan`, and so is the output — both commands render
the same verdict through the same code path.

---

## 4. Authentication

The API requires a bearer token. There are two scopes, and the split is the
same boundary section 7 describes:

| Scope | May do | May not |
| --- | --- | --- |
| `ci` | Submit an artifact, poll a run, request a gate verdict, fetch SARIF | Read the findings list, read artifact bytes, change a finding's status, run triage |
| `admin` | Everything, including the findings corpus and settings | — |

**A build agent gets a `ci` token.** It can submit and be told yes or no; it
cannot read back the corpus of secrets the scan found. That is ADR-0019 made
enforceable rather than merely intended — without a scope, "findings do not
travel to CI" is a convention that the first person to run `curl` breaks.

### First start

Authentication is on by default. A deployment with no tokens mints one admin
token on request, once, rather than printing it to a log at startup — a
console banner is easy to miss, and impossible to recover once it scrolls
past. Open the dashboard and follow its setup wizard, or mint it directly for
a headless environment:

```bash
curl -X POST http://localhost:8000/api/setup/bootstrap
```

Store the token it returns, then mint a scoped one for the pipeline and revoke
the bootstrap:

```bash
docker compose exec api bare token create ci-pipeline --scope ci --expires-in-days 90
docker compose exec api bare token revoke bootstrap
```

(Skip the `dashboard` token step from earlier versions of this doc — the
dashboard now mints and stores its own via the setup wizard.)

`bare token` talks to the database, not the API, and so runs on the
server. That is deliberate: an endpoint that mints credentials is a
privilege-escalation target, and creating the first token must not require
already having one.

### Using it

```bash
export BARE_TOKEN=bare_...      # from your CI secret store
bare scan dist/installer.exe
```

`--token` works too, but prefer the environment variable: an argument shows up
in process listings and in the build log's command echo.

The token is sent as `Authorization: Bearer`. Where a proxy strips that header,
`X-Bare-Token` is accepted as well.

### What the responses mean

| Code | Meaning |
| --- | --- |
| `401` | No token, or one that is unknown, revoked, or expired. Rotate it |
| `403` | Valid token, wrong scope — a `ci` token asked for the findings corpus. Use the right one, do not upgrade the scope |

Every rejection is written to the audit log with the redacted token prefix, the
path, and the caller's address. A burst of them is the first visible sign of
somebody probing the gate.

### Rotation

Tokens carry an optional expiry and a `last_used_at` you can check before
retiring one:

```bash
docker compose exec api bare token list
```

Revocation is a flag, never a delete — "who could reach this API in March, and
who revoked them" is a question a deleted row cannot answer.

---

## 5. Platform recipes

Working workflows live in [`examples/ci/`](../examples/ci/). Summaries follow.

### GitHub Actions

```yaml
- name: Build
  run: msbuild /p:Configuration=Release

- name: BARE release gate
  env:
    BARE_API_URL: ${{ secrets.BARE_API_URL }}
    BARE_TOKEN: ${{ secrets.BARE_TOKEN }}
  run: |
    bare scan dist/installer.exe \
      --sarif bare.sarif \
      --json  bare.json

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bare.sarif
```

`if: always()` on the upload matters: the findings are most worth seeing on the
run that just failed.

The attestation is filled in automatically from `GITHUB_ACTOR` and the run URL,
so the audit log records who triggered the release and which pipeline produced
it. The CLI also appends its verdict to `$GITHUB_STEP_SUMMARY`, which is where
people actually look after a red build.

### GitLab CI

```yaml
release-gate:
  stage: verify
  script:
    - bare scan dist/installer.exe --sarif gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
```

Attestation comes from `GITLAB_USER_LOGIN` and `CI_PIPELINE_URL`.

### Azure DevOps

```yaml
- script: bare scan $(Build.ArtifactStagingDirectory)/installer.exe --json verdict.json
  displayName: BARE release gate
```

Attestation comes from `BUILD_REQUESTEDFOR` and `BUILD_BUILDURI`.

### Jenkins

```groovy
stage('Release gate') {
  steps {
    sh 'bare scan dist/installer.exe --json verdict.json'
  }
}
```

Attestation comes from `CHANGE_AUTHOR` and `BUILD_URL`.

---

## 6. Rolling it out without a revolt

A gate switched on at full strength across an organisation gets switched off
again within a fortnight. Three stages:

**Stage 1 — observe (2–4 weeks).** Add the step with `--warn-only`. It reports
the verdict, uploads SARIF, and always exits 0. Teams see what the gate *would*
do against their real artifacts, and the platform team finds out which rules
are noisy on this codebase before anybody's release depends on the answer.

**Stage 2 — enforce on new.** Drop `--warn-only`, keep `mode: new_only`. From
here nothing new ships. The inherited backlog is visible in every report and
does not block anyone.

**Stage 3 — burn down.** Convert inherited findings into fixes or time-boxed
waivers with owners. When the inherited set is empty, move release branches to
`mode: all`.

Sequencing matters more than it looks. Stage 2 is where the value is — it is
the point at which the leak stops — and it is reachable in weeks. Skipping to
stage 3 is what causes the tool to be uninstalled.

---

## 7. Where the gate sits relative to signing

**Scan the artifact you are going to ship, after it is final and before it is
signed and published.**

- *Before signing* — a signed binary that has to be pulled is a revocation
  problem, not just a rebuild.
- *After every build step that modifies the binary* — installer packaging,
  resource embedding, and obfuscation all run after compilation, and all three
  are places a secret gets baked in. Scanning the pre-packaging executable
  misses exactly what the packaging step added.
- *On the exact bytes that ship.* BARE hashes what it receives and stamps
  the SHA-256 into the run manifest. If the published artifact's hash does not
  match the scanned one, the gate's verdict was about a different file.

For a multi-artifact release, gate each shipped artifact and require all of
them to pass. Recursive unpacking (M2) handles what is *inside* an installer,
so an `.msi` scan covers the executables it carries.

---

## 8. The pipeline's other half: not sending secrets to CI

The gate is evaluated **server-side**. The policy travels to the API; the
findings do not travel back.

A findings list is a company's exposed secrets in one document. Shipping it to
every build agent would spread it into CI logs, artifact stores, and whatever
retains them — re-leaking the exact thing the product exists to catch. The
runner receives a verdict and the masked values behind the violations, and
nothing else.

The same reasoning governs SARIF: masked values only, never plaintext. A SARIF
file is uploaded to a code-scanning service and retained long past the run.

---

## 9. Failure modes and what to do about them

| Symptom | Cause | Response |
| --- | --- | --- |
| Exit 2, "cannot reach" | API unreachable from the runner | Network/firewall. Do not `\|\| true` the step |
| Exit 3 every run | An analyzer is degrading on this artifact | Raise the analyzer's limits. Do not set `on_degraded: pass` |
| Exit 1 on a known-benign value | Genuine false positive | Time-boxed waiver, or a false-positive corpus entry if it is an industry-published value |
| Gate passes but findings exist | `new_only` with inherited findings | Working as designed. Check the INHERITED count |
| Everything is new on the first run | No baseline yet | Expected. The first scan establishes it |

The one anti-pattern worth naming: `bare scan ... || true`. It converts
a gate into a log line. If the gate is too noisy to enforce, fix the policy in
the file where that decision is reviewable — do not neutralise it in a shell.

---

## 10. Air-gapped pipelines

The CLI is standard-library only — no dependency resolution on a locked-down
build image. The scanner runs entirely on-premises with `air_gapped: true` and
`egress_policy: deny`, so the artifact, the findings, and the verdict never
leave the network. Analyzers already have no egress at all; the orchestrator is
the only component that can talk out, and in this configuration it does not.

Where a baseline cannot be resolved from a shared database, supply the
predecessor explicitly with `--baseline-run <id>`.

---

## 11. What is not built yet

Honest list, so nobody plans around something that does not exist:

- **No native GitHub Action / GitLab component.** The recipes above call the
  CLI directly, which works everywhere; a marketplace action is packaging, not
  capability.
- **No PR comment posting.** `--markdown` writes the file and the GitHub job
  summary is written directly; posting it as a review comment is left to the
  platform's own step.
- **Reporting beyond SARIF** (PDF, CycloneDX) is M4.
- **The CLI is not published to a package index.** The examples below show
  `pip install bare` as the shape the install step will take; today a
  runner installs it from the repository (`pip install
  git+https://your-host/bare@vX.Y.Z`) or from a wheel built with
  `uv build` and pushed to an internal index. Pin a tag either way — a release
  gate that silently updates itself is a release gate whose verdict is not
  reproducible.
