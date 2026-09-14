# Security

## Reporting a vulnerability

Report security issues privately. Do not open a public issue.

Include: affected version or commit, a description of the issue, reproduction
steps, and what an attacker gains. We will acknowledge within three business
days and aim to ship a fix or a mitigation within 30 days for anything that
breaks the sandbox boundary or the trust boundary.

We are particularly interested in:

- **Sandbox escapes.** Anything that lets a submitted artifact reach the host,
  the Docker socket, another run's data, or the network.
- **Trust-boundary leaks.** Any path by which secret plaintext, unredacted
  customer data, or artifact contents reach an LLM provider when policy forbids
  it — including via the MCP servers, which must not become a way around the
  pipeline's redaction.
- **Audit integrity.** Anything that lets an action escape the audit log, or an
  attestation be forged or altered after the fact.

Please do not run destructive tests against infrastructure you do not own.

## Responsible use

BARE analyses artifacts you own or are contractually authorized to test.
Every upload requires an attestation recording the attesting identity, a
timestamp, and a free-text authorization reference. That record is written to an
append-only audit log and printed in every report. It is a real gate, not a
checkbox.

### Third-party artifacts and due diligence

M&A and due-diligence analysts assess a target's shipped products without source
access, and people will do this whether or not we bless it. So, plainly:

**Analysing software you did not write can be lawful or unlawful depending on
where you are, how you obtained the artifact, and what you agreed to.** Before
submitting a third-party artifact:

- Check the licence or EULA. Many prohibit reverse engineering outright. Some
  jurisdictions grant statutory rights (for example EU Directive 2009/24/EC
  Article 6 for interoperability) that override such terms; many do not.
- Get authorization in writing, and record its reference in the attestation.
  "Signed diligence agreement, Project Ares, 2026-03-14" is a useful audit
  record. "yes" is not.
- Treat any finding as confidential to the artifact's owner. If BARE
  surfaces a live credential in someone else's product, the right move is
  coordinated disclosure to that vendor — not publication, and not use.
- Do not use findings to compete, to reimplement protected functionality, or to
  access systems you are not authorized to access. A hardcoded credential you
  found is still a credential you may not use.

BARE records the attestation precisely so that this decision is
deliberate, attributable, and auditable. It does not, and cannot, verify that
your authorization is real.

## What this tool will not do

These are product guarantees, not defaults:

- **No offensive output.** No exploit generation, no proof-of-concept payloads,
  no bypass instructions, no key recovery for DRM. Findings describe exposure
  and remediation. If a prompt to the LLM layer requests otherwise, the system
  prompt refuses.
- **No defeating protections.** No anti-anti-debug, no unpacking of commercial
  protectors, no license-check bypass, no DRM circumvention. The pipeline is
  built for cooperative artifacts — the ones you shipped — not hostile ones.
- **No finding without a deterministic anchor.** A model may never assert a
  finding into existence.

## Handling of discovered secrets

A tool that finds secrets is itself a concentrated store of secrets. Therefore:

- Discovered values are stored **hashed and masked** by default. Reports show
  masked values.
- Plaintext retention is opt-in per run. **Today retained values are stored
  unencrypted and never expire**; encryption at rest, a per-run deadline, and an
  audited purge are in review (#12). Leave it off unless a run needs the values.
- Access is by API token with two scopes (ADR-0023): `admin` may read findings
  and retained values; `ci` may submit artifacts and receive a gate verdict, and
  nothing else. There are no per-user roles or SSO yet (M6).
- The append-only audit log records uploads, attestations, rejected
  credentials, token creation and revocation, finding status changes, and run
  recovery. It does **not** yet record plaintext reveals, settings changes,
  report exports, or suppressions (the `audit-completeness` bounty). Model calls
  are recorded separately, in `llm_calls`.

If BARE finds a live credential in your artifact, **rotate it.** Removing
it from the next build is not sufficient — the version already shipped is still
out there, and the finding is evidence it was exposed.

## Deployment hardening

- **The worker holds the Docker socket**, which is root-equivalent on the host.
  Run it on a dedicated host or node pool. Do not co-locate it with workloads
  you would not trust with root. Rootless Podman support is scheduled for M6 for
  operators who cannot accept this; see [THREAT_MODEL.md](THREAT_MODEL.md).
- **Change every default credential** in `.env.example` before any real
  deployment. They are development conveniences.
- **Egress is denied by default.** Leave it that way unless you have
  deliberately configured a cloud LLM provider, and prefer a local model when
  the artifacts are sensitive.
- **Dynamic analysis executes the artifact.** It is off by default and opt-in
  per run. Enable it only on a host you are willing to treat as compromised.
- **Do not expose the dashboard to the internet.** A findings page is a list of
  your exposed secrets.
