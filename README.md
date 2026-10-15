# Reversi

**Reversibility, approvals and tamper-evident evidence for every tool an AI agent can touch.**

Agents write to real systems: orders, payments, tickets, email. When a run goes wrong you need three
answers: *what did it change, why, and how do we undo it?* Reversi sits between an agent and its tools
and answers all three.

- **Tool manifests** declare how reversible each tool is, what undoes it, and which permission it needs.
- **Write-ahead journal**: intent is recorded *before* a tool runs; if journaling fails, the call doesn't run.
- **Saga rollback**: newest first, idempotent, dependency-aware, and it never claims an irreversible
  step was undone.
- **Hash-chained ledger**: edits, deletions and reordering are detectable (Python stdlib, CLI or the browser viewer).
  Arguments and results are hashed, never stored.
- **Approvals and scopes**: irreversible calls need an operator. Agents can't approve themselves or roll back.
- **Observe mode**: journal what *would* be blocked before enforcing anything.

## Try it

```sh
npm install
npm run example      # agent places an order, hits a blocked call, operator rolls it back
open viewer/index.html   # load examples/order-agent/out/ledger.jsonl; the chain is verified in your browser
```

## What's here

| Path | What |
|---|---|
| `packages/reversi` | TypeScript core: manifests, ledger, scopes, engine (`@multimindlab/reversi`) |
| `packages/cli` | `reversi validate / verify / runs / plan / rollback / export` |
| `packages/gateway` | MCP gateway, observe mode (`reversi-gateway`) |
| `packages/server` | HTTP API (Hono) with agent and operator API keys |
| `packages/sdk-py` | Python client and offline verifier, stdlib only (`reversi-sdk`) |
| `viewer/` | Single-file trace viewer |
| `examples/` | TypeScript and Python agents |
| `docs/` | Mintlify docs (`reversi-docs.multimind.dev`) |
| `schemas/`, `conformance/` | JSON Schemas and cross-language test fixtures |

## Honest status

Built and tested: everything in the table above. **Not built:** MCP gateway enforcement (it only observes), Postgres store,
a hosted dashboard, content checks for prompt injection. Reversi enforces what manifests declare;
it cannot discover what a tool really does, and the ledger is tamper-*evident*, not tamper-proof.
Read [docs/limits.mdx](docs/limits.mdx) before relying on it.

## License

Apache 2.0. See [LICENSE](LICENSE).
