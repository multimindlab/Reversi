# Reversi

**Reversibility, approvals, policy and tamper-evident evidence for every tool an AI agent can touch.**

Agents write to real systems: orders, payments, tickets, email. When a run goes wrong you need three
answers: *what did it change, why, and how do we undo it?* Reversi sits between an agent and its tools
and answers all three.

- **Tool manifests** declare how reversible each tool is, what undoes it, and which permission it needs.
- **Write-ahead journal**: intent is recorded *before* a tool runs; if journaling fails, the call doesn't run.
- **Saga rollback**: newest first, idempotent, dependency-aware, with retries and verification. It never claims an
  irreversible step was undone, and unknown outcomes are reconciled by a human, not guessed.
- **Hash-chained ledger** on files, SQLite or PostgreSQL: edits, deletions and reordering are detectable. Arguments and
  results are hashed, never stored; credentials in free text are redacted.
- **Policy as code**: allow/deny/approve rules, rate limits, environments, tests (`reversi policy test`), plus content
  checks for credentials, hidden payloads, injection phrasing and exfiltration sequences.
- **Approvals**: queued, bound to the exact arguments, single use, expiring, persisted, with webhook notification.
- **MCP gateway**: put it in front of any MCP server (stdio or Streamable HTTP) to journal, enforce, approve and roll
  back without changing the agent. Operator tools live on a separate authenticated endpoint.
- **Console, API and metrics**: roles (agent, auditor, approver, operator, admin), key rotation, OIDC, Prometheus,
  kill switch, signed evidence bundles and auditor reports.
- **Connectors** for filesystem, GitHub, Slack and Stripe with working compensations.

## Try it

```sh
npm install
npm run example      # agent places an order, hits a blocked call, operator rolls it back
open viewer/index.html   # load examples/order-agent/out/ledger.jsonl; the chain is verified in your browser
```

Node 22.13+ is required. For the gateway, see [examples/gateway](examples/gateway) and the
[gateway guide](docs/gateway.mdx).

## What's here

| Path | What |
|---|---|
| `packages/reversi` | Core: manifests, ledger, engine, policy, content checks, approvals, evidence, stores, auth (`@multimindlab/reversi`) |
| `packages/cli` | `reversi` command line |
| `packages/server` | HTTP API, operator console and metrics (Hono) |
| `packages/gateway` | MCP gateway (`reversi-gateway`) |
| `packages/connectors` | Filesystem, GitHub, Slack, Stripe connectors and `reversi-connectors` |
| `packages/sdk-py` | Python client and offline verifier, stdlib only (`reversi-sdk`) |
| `viewer/` | Single-file trace viewer |
| `examples/` | TypeScript, Python and gateway examples |
| `docs/` | Mintlify docs (`docs/docs.json` is the navigation) |
| `deploy/`, `Dockerfile` | Docker image and a Compose stack on PostgreSQL |
| `schemas/`, `conformance/` | JSON Schemas and cross-language test fixtures |

## Honest status

Built and tested with unit and integration tests, including a live PostgreSQL run and real stdio processes.
**Not exercised here:** the connectors against live GitHub, Slack and Stripe (they are tested against fakes of those
APIs), the Dockerfile, Compose stack and GitHub workflows (written, not executed). **Not built:** OpenTelemetry traces,
risk scoring, retention tooling, framework adapters, a hosted service. Reversi enforces what manifests declare; it
cannot discover what a tool really does, content checks are heuristics, and the ledger is tamper-*evident*, not
tamper-proof. Read [limits](docs/limits.mdx) and the [threat model](docs/threat-model.mdx) before relying on it.

## Docs

The docs are Mintlify pages in [docs/](docs). To publish them, connect this repository in the Mintlify dashboard, install
its GitHub app, and set the docs directory to `/docs` (a monorepo setup); Mintlify then rebuilds on every push to the
configured branch.

## License

Apache 2.0. See [LICENSE](LICENSE).
