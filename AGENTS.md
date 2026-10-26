# Muistamo

The company's AI knowledge and workforce ledger. Muistamo turns what employees teach AI agents into
reviewed, versioned company knowledge that survives staff turnover; gives every agent an owner, an
identity and an HR-driven lifecycle; meters every model call to an agent, a person and a cost centre
with no markup; and serves that knowledge into whichever AI tool people already use (Copilot,
ChatGPT, Claude, Gemini, coding agents) through MCP and Agent Skills.

Full requirements: `docs/prd.md`. Product rationale and decisions D1–D51: `docs/definition.md`.
When a task names a requirement (FR-xxx), an epic (E-xx.x) or a journey (J-x), read it there first
rather than inferring it from the prompt.

## Release 1 scope

Release 1 is deliberately narrow: the leaver wedge and the knowledge thesis, with **one integration
of each kind** — one HRIS, one identity provider (Entra), one assistant, one document source.
`docs/prd.md` section 2a is the canonical scope table. If a task seems to need a second connector,
a second IdP, bi-temporal knowledge, endpoint enforcement or the open-core release, stop and ask:
those are release 2 and the answer is usually "not yet".

The slice that must work end to end before anything else: an HR joiner event creates an instance
with its own identity → it answers a question from a knowledge pack with citations → a correction
is captured and merged after review → a leaver event suspends it and revokes its keys → the
evidence log shows all of it.

## Invariants

These are the product. Breaking one is worse than shipping nothing. Never weaken one to make a test
pass or a feature work — raise it with the human instead.

1. **Authorisation at use time.** Retrieval and tool calls are authorised against the acting
   person's own rights at the moment of the call, per connector. Never only at pack configuration
   time. A broadly privileged service account is never an acceptable retrieval path.
2. **An agent can never see more than the person it acts for.** Effective permission is the
   intersection of the template's scope, the human's own access and the link's limits.
3. **Fail closed.** If authorisation cannot be established, sensitive actions and writes are
   refused. Degraded modes are bounded, logged and never silently widen access.
4. **Evidence before return.** Every consequential action writes a signed, hash-chained evidence
   event before the action returns. If the evidence write cannot be persisted, refuse the action.
5. **Deletion is complete.** Deleting a knowledge entry deletes its embeddings, cached extracts and
   index entries within 24 hours, and records proof. Nothing derived from customer content is used
   to train models.
6. **Residency holds.** Customer content and derived data stay in the agreed region. Failover never
   crosses the boundary; the service degrades instead.
7. **No markup.** Model usage is passed through at provider cost. Metering must be accurate enough
   to stand behind that claim.
8. **Honest coverage.** We report what is governed, observed-only and blind (`docs/prd.md` 12a).
   Never write code or copy that implies Muistamo sees calls it does not see.

## Architecture

Monorepo. Services talk over HTTP/gRPC using the generated contracts; no service reaches into
another's database.

| Path | Language | Responsibility |
| --- | --- | --- |
| `contracts/` | OpenAPI + JSON Schema | **Source of truth** for API and YAML kinds. Types are generated from here for every language — never hand-write a type that exists here |
| `control-plane/` | Go | Registry (templates, instances, clones), identity, lifecycle, policy, evidence, billing |
| `knowledge/` | Python | Packs, layers, capture, proposals, review and merge, retrieval, MCP server |
| `runtime/` | Python | Thin agent runtime: web and Teams surfaces, tool calls |
| `console/` | TypeScript | Next.js admin and review UI |
| `cli/` | Go | `mst` CLI |
| `docs/` | — | Definition and PRD |

**Naming conventions** (decision D51): API group `muistamo.dev/v1`; Terraform resources
`muistamo_agent_link`; CLI `mst`; Go packages lower case, no underscores; Python modules snake_case.

**Key dependencies**: PostgreSQL 17 with row-level security per tenant, pgvector, Temporal for
durable workflows, OpenFGA for relationships, Cedar for action rules, OpenTelemetry GenAI
conventions for traces. The gateway core (agentgateway vs Agent Router) is **still open** —
decision D28. Do not write code that assumes either until it is decided.

## Commands

```bash
make setup        # install dependencies for all services
make test         # all tests — must pass before any commit
make test-authz   # adversarial permission suite — must pass, never skip or weaken
make lint         # golangci-lint, ruff, eslint
make generate     # regenerate types from contracts/ — run after any contract change
make dev          # docker compose: postgres, temporal, openfga, services
```

## Conventions

- **Contracts first.** Change `contracts/`, run `make generate`, then implement. Never let the Go
  and Python sides drift.
- **Tests with the code**, in the same commit. For anything touching permissions, deletion,
  revocation or evidence, write the test first.
- **Migrations are forward-only** and reviewed by a human before merge.
- **Errors carry context**: wrap in Go, no bare `except` in Python.
- **No secrets in code, logs or tests.** Provider keys live in the customer's vault; test fixtures
  use obviously fake values.
- **Structured logging** with the agent, person and request identifiers on every entry.
- Prefer boring, explicit code. This is infrastructure people audit.

## Working agreement

- **Plan structural work first** and wait for approval. Small, well-specified changes can proceed
  directly.
- **One task per session.** Ask for the acceptance criteria if the task does not name them.
- **Run `make test` and `make test-authz` before saying a task is done.** Do not report success on
  unverified code.
- **Stop and ask** when: a task would breach an invariant; it needs a second connector or IdP; it
  depends on the undecided gateway core; it touches cryptographic signing or the evidence chain; or
  the requirement in `docs/prd.md` contradicts the prompt.
- Do not add dependencies without saying why in the commit message. Prefer the ones already in the
  PRD tech stack.
- Do not create files unless the task needs them. No speculative abstractions, no README per folder.

## Areas needing human review

Write these if asked, but flag them clearly for line-by-line review and never merge them
unsupervised: authorisation and permission intersection, token handling and revocation, the
evidence hash chain and signing, retention and deletion paths, anything in the gateway's policy
path, and database schema changes.
## Standing rules from the maintainer

- **Never merge a pull request unless the maintainer asks.** Open it, wait for CI, and report.
- **Before a merge, have the change reviewed independently** (another agent or a human reading the
  diff against the invariants above), and fix what the review finds first.
- **Ask product questions before structural work**: offer the options with a recommendation, then
  plan, then build.
- **Verify like an auditor.** Besides `make lint test test-authz`, check each new security rule with
  a mutation (remove the rule; a test must fail) and run the feature end to end with real binaries.
- **After every merge, update `docs/progress.md`** (what merged, what changed in the requirement
  table, open decisions). It is local-only, see below.
- **Stacked PRs**: control-plane migrations (goose) must apply in order, so a PR with a migration
  branches from the open PR whose migration precedes it.

## Local-only files

`docs/` (the PRD, the definition and `progress.md`) is not in the repository. Agents running on the
maintainer's machine can read it. An agent working from a clone (a cloud session, a hosted coding
agent) will not have it: if a task names an FR, epic or journey and `docs/prd.md` is missing, ask
for the relevant text rather than guessing.

## Environment

- **Toolchain**: Go per `go.mod` (the toolchain line is fetched automatically), Python 3.12 with
  uv, Node 22+ (CI uses 24), OpenTofu 1.13.2 for the Terraform provider's acceptance tests, GNU
  make, Docker. `make setup` installs golangci-lint into `bin/`.
- **Database and Temporal**: `make test` starts PostgreSQL 17 (pgvector) and Temporal from
  `deploy/dev/compose.yaml`. If a local PostgreSQL holds port 5432, pass `POSTGRES_PORT=55432`.
  `TEST_DB_EXTERNAL=1` uses services that are already running.
- **Windows**: works natively with Git Bash on PATH. Heredocs in some agent shells collapse
  backslashes; write files with the agent's file tools instead.
