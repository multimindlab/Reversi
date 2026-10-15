"""End to end: the Python client against the real TypeScript server (skipped if Node or the build is missing)."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from reversi_sdk import Blocked, EffectUncertain, ReversiClient, ReversiError, parse_jsonl, verify_records

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MAIN = os.path.join(ROOT, "packages", "server", "dist", "main.js")

MANIFESTS = [
    {"tool": "create_order", "effect": "reversible", "permission": "orders:write",
     "compensation": {"tool": "cancel_order", "argument_map": {"id": "$result.id"}}},
    {"tool": "cancel_order", "effect": "idempotent", "permission": "orders:write"},
    {"tool": "send_email", "effect": "irreversible", "permission": "mail:send"},
]


@unittest.skipUnless(shutil.which("node") and os.path.exists(MAIN), "needs node and `npm run build`")
class LiveServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="reversi-py-")
        with open(os.path.join(cls.tmp, "tools.json"), "w") as f:
            json.dump(MANIFESTS, f)
        with open(os.path.join(cls.tmp, "keys.json"), "w") as f:
            json.dump([
                {"name": "py-agent", "role": "agent", "key": "agent-key"},
                {"name": "ops", "role": "operator", "key_sha256": hashlib.sha256(b"ops-key").hexdigest()},
            ], f)
        env = dict(os.environ, REVERSI_MANIFESTS=os.path.join(cls.tmp, "tools.json"),
                   REVERSI_KEYS=os.path.join(cls.tmp, "keys.json"), REVERSI_DATA=os.path.join(cls.tmp, "data"),
                   PORT="0", HOST="127.0.0.1")
        cls.proc = subprocess.Popen(["node", MAIN], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        line = cls.proc.stdout.readline()
        m = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not m:
            cls.proc.kill()
            raise RuntimeError(f"server did not start: {line!r}")
        cls.url = f"http://127.0.0.1:{m.group(1)}"

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=5)
        cls.proc.stdout.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_agent_journals_operator_rolls_back_and_evidence_verifies(self):
        agent = ReversiClient(self.url, "agent-key")
        ops = ReversiClient(self.url, "ops-key")
        run = agent.start_run(["orders:write"], run_id="py-1")
        out = run.call("create_order", "customer asked", lambda a: {"id": 99}, args={"sku": "A1"})
        self.assertEqual(out, {"id": 99})

        # policy: out-of-scope tool is refused and never executed
        ran = []
        with self.assertRaises(Blocked):
            run.call("send_email", "confirm", lambda a: ran.append(1))
        self.assertEqual(ran, [])

        # failures and uncertainty are journaled, then re-raised
        with self.assertRaises(EffectUncertain):
            run.call("create_order", "retry", lambda a: (_ for _ in ()).throw(EffectUncertain("timeout")))
        self.assertEqual(run.state()["unresolved"], [1])

        # the agent key cannot reach the operator plane
        with self.assertRaises(ReversiError) as cm:
            run.plan()
        self.assertEqual(cm.exception.status, 403)

        op = ops.run("py-1")
        plan = op.plan()
        self.assertEqual(plan["actions"][0]["kind"], "unresolved")
        self.assertEqual(plan["actions"][1]["compensation_tool"], "cancel_order")
        start = op.begin_compensation(0)
        self.assertEqual(start["decision"], "go")
        self.assertEqual(start["call"]["args"], {"id": 99})
        op.complete_compensation(0, ok=True)

        recs = parse_jsonl(op.export_jsonl())
        self.assertTrue(verify_records(recs).ok)
        self.assertNotIn("A1", json.dumps(recs))
        self.assertTrue(ops.verify_ledger()["ok"])

    def test_bad_key_is_rejected(self):
        with self.assertRaises(ReversiError) as cm:
            ReversiClient(self.url, "nope").start_run(["orders:write"])
        self.assertEqual(cm.exception.status, 401)


if __name__ == "__main__":
    unittest.main()
