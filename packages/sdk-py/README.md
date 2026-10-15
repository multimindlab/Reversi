# reversi-sdk

Python SDK for [Reversi](https://reversi.multimind.dev): journal an agent's tool calls through a Reversi
server, and verify ledgers offline. Standard library only (Python 3.9+).

```python
from reversi_sdk import ReversiClient
run = ReversiClient("http://127.0.0.1:7421", api_key="...").start_run(["orders:write"])
run.call("create_order", "customer asked", lambda args: {"order_id": "o1"}, args={"sku": "A1"})
```

Beyond the agent calls: decorate tools with `@run.tool(...)`, handle `Blocked.approval_id` when a call needs an
approver, and with operator keys use `run.resolve(...)`, `run.rollback(compensate)` (retries with the same idempotency
key), `client.approvals()`, `client.approve(id)`, `client.halt(reason)` and `run.bundle()` (signed evidence).

`python -m reversi_sdk verify ledger.jsonl` checks a ledger's hash chain. Docs: https://reversi-docs.multimind.dev
