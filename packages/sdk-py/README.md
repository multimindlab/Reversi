# reversi-sdk

Python SDK for [Reversi](https://reversi.multimind.dev): journal an agent's tool calls through a Reversi
server, and verify ledgers offline. Standard library only (Python 3.9+).

```python
from reversi_sdk import ReversiClient
run = ReversiClient("http://127.0.0.1:7421", api_key="...").start_run(["orders:write"])
run.call("create_order", "customer asked", lambda args: {"order_id": "o1"}, args={"sku": "A1"})
```

`python -m reversi_sdk verify ledger.jsonl` checks a ledger's hash chain. Docs: https://reversi-docs.multimind.dev
