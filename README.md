<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/dark.png">
    <img src="docs/logo/light.png" alt="Reversi logo" width="140">
  </picture>
</p>

# Reversi

**Reversibility, approvals, policy and tamper-evident evidence for every tool an AI agent can touch.**

Agents write to real systems: orders, payments, tickets, email. When a run goes wrong you need three
answers: *what did it change, why, and how do we undo it?* Reversi sits between an agent and its tools
and answers all three.

- **Tool manifests** declare how reversible each tool is, what undoes it, and which permission it needs. They live in a
  versioned, signable registry (drafts, approval, deprecation) and can be drafted from an MCP server's own tool list.
- **Write-ahead journal**: intent is recorded *before* a tool runs; if journaling fails, the call doesn't run.
- **Saga rollback**: newest first, idempotent, dependency-aware, with retries and read-back verification. It never claims an
  irreversible step was undone, and unknown outcomes are reconciled by a human, not guessed.
- **Hash-chained ledger** on files, SQLite or PostgreSQL: edits, deletions and reordering are detectable. Arguments and
  results are hashed, never stored; credentials in free text are redacted. Heads can be anchored outside the system.
- **Policy as code**: allow/deny/approve rules, rate limits, environments, risk scoring, tests (`reversi policy test`), plus content
  checks for credentials, hidden payloads, injection phrasing and exfiltration sequences. Simulate a policy change against
  captured history before you publish it.
- **Approvals**: queued, bound to the exact arguments, single use, expiring, persisted; quorum, group routing, escalation,
  delegation and break-glass; notified over Slack, Teams, email, PagerDuty, Opsgenie or a signed webhook.
- **MCP gateway**: put it in front of any MCP server (stdio or Streamable HTTP). With no manifests it starts in observe mode and
  shows what to classify; then enforce, advise or observe, with schema validation, timeouts, retries and read-backs. Operator
  tools live on a separate authenticated endpoint.
- **Console, API and metrics**: a server-rendered console (off by default; open on localhost, or login) to decide approvals, run
  rollbacks and edit manifests and policy; roles (agent, auditor, approver, operator, admin), key rotation, OIDC, Prometheus,
  OpenTelemetry, kill switches, signed evidence bundles and auditor reports.
- **GitOps**: `reversi.config.yaml`, `reversi apply` to make a registry match a directory in git, hot reload, retention and legal holds.
- **Connectors** for fourteen systems (filesystem, GitHub, GitLab, Slack, Teams, Linear, Jira, Stripe, Google Calendar, Postgres,
  S3, Cloud Storage, Blob Storage, Kubernetes) with working compensations and a certification suite.

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
| `packages/cli` | `reversi` command line (init, doctor, lint, test, apply, inspect, rollback, approvals, simulation) |
| `packages/server` | HTTP API, operator console and metrics (Hono) |
| `packages/gateway` | MCP gateway (`reversi-gateway`) |
| `packages/connectors` | Fourteen connectors and `reversi-connectors` |
| `packages/sdk-py` | Python client, offline verifier, Pydantic bindings and framework adapters (`reversi-sdk`) |
| `viewer/` | Single-file trace viewer |
| `examples/` | TypeScript, Python and gateway examples |
| `docs/` | Mintlify docs (`docs/docs.json` is the navigation) |
| `deploy/`, `Dockerfile` | Docker image, a Compose stack on PostgreSQL, and a Helm chart (`deploy/helm/reversi`) |
| `schemas/`, `conformance/` | JSON Schemas and cross-language test fixtures |

## Honest status

Built and tested with unit and integration tests, including a live PostgreSQL run and real stdio processes.

**Built but not exercised against real systems:** the fourteen connectors (tested against fakes of each API, except the local
filesystem one), notification channels and OpenTelemetry export (tested against local fake receivers), the Python framework
adapters (tested against fakes of each framework), the Dockerfile, the Compose stack, the **Helm chart (never installed on a
cluster; `helm` was not available to lint it)** and the GitHub workflows (written, not run).

**Not built:** a Terraform provider, a Kubernetes operator (use `reversi apply` and the Helm chart), OIDC browser redirect login
for the console (login takes a pasted API key or access token), a hosted control plane, Go and Java SDKs, clustering with run
hand-off, gateway passthrough of MCP resources, prompts and sampling, and an external security review.

Reversi enforces what manifests declare; it cannot discover what a tool really does, content checks are heuristics, and the
ledger is tamper-*evident*, not tamper-proof. Read [limits](docs/limits.mdx), the [roadmap](docs/roadmap.mdx) and the
[threat model](docs/threat-model.mdx) before relying on it.

## Docs

The docs are Mintlify pages in [docs/](docs). To publish them, connect this repository in the Mintlify dashboard, install
its GitHub app, and set the docs directory to `/docs` (a monorepo setup); Mintlify then rebuilds on every push to the
configured branch.

## License

Apache 2.0. See [LICENSE](LICENSE).
