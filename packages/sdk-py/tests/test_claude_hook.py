"""The Claude Code hook, end to end: against an in-process fake Reversi, and against the real built server."""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from reversi_sdk import ReversiClient
from reversi_sdk.integrations import claude_code_hook as hook

from ._fake_reversi import APPROVAL, FakeReversi

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
MAIN = os.path.join(ROOT, "packages", "server", "dist", "main.js")
CLI = os.path.join(ROOT, "packages", "cli", "dist", "main.js")


def run_hook(payload, env, post=False):
    out = io.StringIO()
    code = hook.main(["--post"] if post else [], io.StringIO(json.dumps(payload)), out, env)
    assert code == 0
    return json.loads(out.getvalue())["hookSpecificOutput"] if out.getvalue() else None


def pre(session="s1", tool="Read", inp=None, tid="tu1"):
    return {"hook_event_name": "PreToolUse", "session_id": session, "tool_name": tool,
            "tool_input": inp or {"file_path": "/a"}, "tool_use_id": tid}


class ToolNameMapping(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(hook.map_tool_name("Bash"), "Bash")
        self.assertEqual(hook.map_tool_name("mcp__github__create_issue"), "github.create_issue")
        self.assertEqual(hook.map_tool_name("mcp__my_server__do__it"), "my_server.do__it")


class HookAgainstFake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeReversi().start()

    @classmethod
    def tearDownClass(cls):
        cls.fake.stop()

    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="hookstate-")
        self.addCleanup(shutil.rmtree, self.state, True)
        self.env = {"REVERSI_URL": self.fake.url, "REVERSI_AGENT_KEY": "agent-key", "REVERSI_PERMISSIONS": "a, b",
                    "REVERSI_HOOK_STATE": self.state}
        self.session = "sess-" + self.id().split(".")[-1]

    def steps(self):
        return self.fake.runs[f"claude-{self.session}"]["steps"]

    def test_allow_creates_one_run_per_session_and_maps_mcp_names(self):
        d = run_hook(pre(self.session, "mcp__srv__lookup"), self.env)
        self.assertEqual(d["hookEventName"], "PreToolUse")
        self.assertEqual(d["permissionDecision"], "allow")
        run_hook(pre(self.session, "Read", tid="tu2"), self.env)
        self.assertEqual([s["tool"] for s in self.steps()], ["srv.lookup", "Read"])
        self.assertEqual(self.fake.runs[f"claude-{self.session}"]["permissions"], ["a", "b"])
        creates = [r for r in self.fake.requests if r[:2] == ("POST", "/v1/runs") and r[2]["run_id"] == f"claude-{self.session}"]
        self.assertEqual(len(creates), 1)

    def test_would_block_is_allowed(self):
        d = run_hook(pre(self.session, "would_x"), self.env)
        self.assertEqual(d["permissionDecision"], "allow")
        self.assertIn("dry run", d["permissionDecisionReason"])

    def test_pending_approval_asks_and_names_the_request(self):
        d = run_hook(pre(self.session, "approve_deploy"), self.env)
        self.assertEqual(d["permissionDecision"], "ask")
        self.assertIn(APPROVAL, d["permissionDecisionReason"])

    def test_other_block_denies(self):
        d = run_hook(pre(self.session, "blocked_x"), self.env)
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("tool is not in scope", d["permissionDecisionReason"])

    def test_post_reports_success_for_the_recorded_step(self):
        run_hook(pre(self.session, "Read", tid="a"), self.env)
        run_hook(pre(self.session, "Read", tid="b"), self.env)
        self.assertIsNone(run_hook({"hook_event_name": "PostToolUse", "session_id": self.session, "tool_name": "Read",
                                    "tool_use_id": "b", "tool_response": {"content": "x"}}, self.env, post=True))
        self.assertIsNone(self.steps()[0]["outcome"])
        self.assertEqual(self.steps()[1]["outcome"], {"status": "succeeded", "result": {"content": "x"}})
        # reporting twice does nothing: the state entry is consumed
        before = len(self.fake.requests)
        run_hook({"session_id": self.session, "tool_name": "Read", "tool_use_id": "b"}, self.env, post=True)
        self.assertEqual(len(self.fake.requests), before)

    def test_post_failure_and_error_response_report_failed(self):
        run_hook(pre(self.session, "Bash", tid="f1"), self.env)
        run_hook(pre(self.session, "Bash", tid="f2"), self.env)
        run_hook({"hook_event_name": "PostToolUseFailure", "session_id": self.session, "tool_name": "Bash",
                  "tool_use_id": "f1", "error": "exit 1"}, self.env, post=True)
        run_hook({"session_id": self.session, "tool_name": "Bash", "tool_use_id": "f2",
                  "tool_response": {"is_error": True, "error": "nope"}}, self.env, post=True)
        self.assertEqual([s["outcome"]["status"] for s in self.steps()], ["failed", "failed"])
        self.assertEqual(self.steps()[0]["outcome"]["error"], "exit 1")

    def test_post_without_pre_record_is_a_noop(self):
        before = len(self.fake.requests)
        run_hook({"session_id": self.session, "tool_name": "Read", "tool_use_id": "zzz"}, self.env, post=True)
        self.assertEqual(len(self.fake.requests), before)

    def test_post_works_without_tool_use_id(self):
        run_hook({**pre(self.session, "Read"), "tool_use_id": None}, self.env)
        run_hook({"session_id": self.session, "tool_name": "Read", "tool_input": {"file_path": "/a"}}, self.env, post=True)
        self.assertEqual(self.steps()[0]["outcome"]["status"], "succeeded")

    def test_fail_closed_when_unreachable_and_fail_open_when_configured(self):
        env = dict(self.env, REVERSI_URL="http://127.0.0.1:9", REVERSI_TIMEOUT="1")
        d = run_hook(pre(self.session), env)
        self.assertEqual(d["permissionDecision"], "deny")
        self.assertIn("failing closed", d["permissionDecisionReason"])
        d = run_hook(pre(self.session), dict(env, REVERSI_HOOK_FAIL_OPEN="1"))
        self.assertEqual(d["permissionDecision"], "allow")
        self.assertIn("FAIL_OPEN", d["permissionDecisionReason"])

    def test_missing_config_bad_key_and_bad_input_deny(self):
        self.assertEqual(run_hook(pre(self.session), {})["permissionDecision"], "deny")
        d = run_hook(pre(self.session), dict(self.env, REVERSI_AGENT_KEY="wrong"))
        self.assertEqual(d["permissionDecision"], "deny")
        out = io.StringIO()
        hook.main([], io.StringIO("not json"), out, self.env)
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")
        d = run_hook({"tool_name": "Read"}, self.env)
        self.assertEqual(d["permissionDecision"], "deny")

    def test_post_never_raises_when_server_is_down(self):
        run_hook(pre(self.session, "Read", tid="d1"), self.env)
        env = dict(self.env, REVERSI_URL="http://127.0.0.1:9", REVERSI_TIMEOUT="1")
        self.assertIsNone(run_hook({"session_id": self.session, "tool_name": "Read", "tool_use_id": "d1"}, env, post=True))

    def test_console_script_is_declared(self):
        with open(os.path.join(ROOT, "packages", "sdk-py", "pyproject.toml"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn('reversi-claude-hook = "reversi_sdk.integrations.claude_code_hook:main"', text)

    def test_runs_as_a_subprocess_like_claude_code_does(self):
        env = dict(os.environ, **self.env)
        p = subprocess.run(["python3", "-m", "reversi_sdk.integrations.claude_code_hook"],
                           input=json.dumps(pre(self.session, "Read")), capture_output=True, text=True, env=env,
                           cwd=os.path.join(ROOT, "packages", "sdk-py"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "allow")


MANIFESTS = [
    {"tool": "Read", "effect": "read_only", "permission": "claude:read"},
    {"tool": "Bash", "effect": "irreversible", "permission": "claude:shell"},
    {"tool": "Write", "effect": "idempotent", "permission": "claude:write"},
]


@unittest.skipUnless(shutil.which("node") and os.path.exists(MAIN), "needs node and `npm run build`")
class HookAgainstRealServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="reversi-hook-")
        with open(os.path.join(cls.tmp, "tools.json"), "w") as f:
            json.dump(MANIFESTS, f)
        with open(os.path.join(cls.tmp, "keys.json"), "w") as f:
            json.dump([{"name": "claude", "role": "agent", "key": "agent-key"},
                       {"name": "appr", "role": "approver", "key": "appr-key"},
                       {"name": "ops", "role": "operator", "key_sha256": hashlib.sha256(b"ops-key").hexdigest()}], f)
        subprocess.run(["node", CLI, "keygen", os.path.join(cls.tmp, "sign")], check=True, capture_output=True)
        env = dict(os.environ, REVERSI_SIGNING_KEY=os.path.join(cls.tmp, "sign.key"),
                   REVERSI_MANIFESTS=os.path.join(cls.tmp, "tools.json"), REVERSI_KEYS=os.path.join(cls.tmp, "keys.json"),
                   REVERSI_DATA=os.path.join(cls.tmp, "data"), PORT="0", HOST="127.0.0.1")
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

    def test_allow_ask_approve_allow_deny_and_outcome(self):
        state = os.path.join(self.tmp, "hookstate")
        env = {"REVERSI_URL": self.url, "REVERSI_AGENT_KEY": "agent-key", "REVERSI_PERMISSIONS": "claude:read,claude:shell",
               "REVERSI_HOOK_STATE": state}
        d = run_hook(pre("live", "Read", tid="t1"), env)
        self.assertEqual(d["permissionDecision"], "allow", d)
        run_hook({"session_id": "live", "tool_name": "Read", "tool_use_id": "t1", "tool_response": {"ok": True}}, env, post=True)

        d = run_hook(pre("live", "Bash", {"command": "ls"}, tid="t2"), env)
        self.assertEqual(d["permissionDecision"], "ask", d)
        aid = re.search(r"apr_[0-9a-f-]+", d["permissionDecisionReason"]).group(0)
        appr = ReversiClient(self.url, "appr-key")
        self.assertEqual([a["id"] for a in appr.approvals(status="pending")], [aid])
        appr.approve(aid, "ok")
        d = run_hook(pre("live", "Bash", {"command": "ls"}, tid="t3"), env)
        self.assertEqual(d["permissionDecision"], "allow", d)

        d = run_hook(pre("live", "Write", tid="t4"), env)  # claude:write was not granted to the run
        self.assertEqual(d["permissionDecision"], "deny", d)

        run_hook({"session_id": "live", "tool_name": "Bash", "tool_use_id": "t3", "tool_response": {"stdout": ""}}, env, post=True)
        st = ReversiClient(self.url, "ops-key").run("claude-live").state()
        self.assertEqual(st["unresolved"], [])


if __name__ == "__main__":
    unittest.main()
