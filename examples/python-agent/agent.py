"""A Python agent calling tools through a running Reversi server.

1. Start the server (see docs quickstart):
     REVERSI_MANIFESTS=examples/order-agent/manifests REVERSI_KEYS=examples/python-agent/keys.json \
       node packages/server/dist/main.js
   (the manifests are YAML; the server reads YAML and JSON)
2. python examples/python-agent/agent.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "packages", "sdk-py"))
from reversi_sdk import Blocked, ReversiClient  # noqa: E402

client = ReversiClient(os.environ.get("REVERSI_URL", "http://127.0.0.1:7421"), os.environ.get("REVERSI_AGENT_KEY", "agent-demo-key"))
run = client.start_run(["customers:read", "orders:write", "payments:write"], reason="python demo")

order = run.call("create_order", "customer asked for BOOK-1", lambda args: {"order_id": "ord_py_1"}, args={"sku": "BOOK-1"})
print("created", order)
run.call("charge_card", "pay for the order", lambda args: {"charge_id": "ch_py_1"}, args={"amount": 25})

try:
    run.call("send_confirmation_email", "send receipt", lambda args: "sent")  # not in scope, needs approval
except Blocked as e:
    print("blocked:", e)

print("run", run.run_id, "journaled. An operator can now review and roll it back:")
print(f"  curl -H 'Authorization: Bearer <operator key>' {client.base_url}/v1/runs/{run.run_id}/plan")
