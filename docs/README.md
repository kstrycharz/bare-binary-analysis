# Documentation

Operator and developer guides. The four top-level documents are the entry
points:

- `README.md` — what BARE is and how to run it
- `ARCHITECTURE.md` — components, sandbox boundary, pipeline, data model
- `THREAT_MODEL.md` — what the sandbox defends against, and what it does not
- `SECURITY.md` — vulnerability reporting and responsible use

`CLAUDE.md` is the working document: current status, known issues, and the
conventions the code is held to. `ADR.md` records architecture decisions with
their rejected alternatives.

`CONTAINERS.md` describes every container in a deployment: what it does, what
it talks to, what happens when it dies, and which of them hold privilege.

`feature-request.md` in the repository root is the bounty list: wanted features,
each scoped so someone can build it on a branch and have it judged on whether it
works. Start there if you are looking for something to pick up.
