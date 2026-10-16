"""Framework adapters, tested against small fakes of the framework interfaces (the frameworks are not installed)."""
import dataclasses
import sys
import types
import unittest

from reversi_sdk import Blocked, EffectUncertain, ReversiClient
from reversi_sdk.integrations import crewai as rcrew
from reversi_sdk.integrations import fastmcp as rmcp
from reversi_sdk.integrations import langgraph as rlg
from reversi_sdk.integrations import openai_agents as roa

from ._fake_reversi import APPROVAL, FakeReversi


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeReversi().start()

    @classmethod
    def tearDownClass(cls):
        cls.fake.stop()

    def setUp(self):
        self.client = ReversiClient(self.fake.url, "agent-key")
        self.run = self.client.start_run(["p"], run_id=f"r-{self.id().split('.')[-1]}")
        self.steps = lambda: self.fake.runs[self.run.run_id]["steps"]


class FakeBaseTool:
    """Mimics langchain_core.tools.BaseTool: name, description, invoke(input)."""
    name = "lookup"
    description = "look things up"

    def __init__(self):
        self.calls = []

    def invoke(self, input, config=None):
        self.calls.append(input)
        return {"found": input}


class LangGraphTests(Base):
    def test_function_is_journaled_and_keeps_signature(self):
        @rlg.reversible_tool(self.run, "lookup", reason="test")
        def lookup(sku: str, qty: int = 1):
            """doc"""
            return {"sku": sku}

        self.assertEqual(lookup("A1", qty=2), {"sku": "A1"})
        self.assertEqual(lookup.__name__, "lookup")
        self.assertEqual(lookup.__doc__, "doc")
        self.assertEqual(self.steps()[0]["args"], {"args": ["A1"], "kwargs": {"qty": 2}})
        self.assertEqual(self.steps()[0]["outcome"]["status"], "succeeded")

    def test_basetool_proxy_journals_invoke_and_passes_attributes(self):
        inner = FakeBaseTool()
        t = rlg.reversible_tool(self.run, "lookup")(inner)
        self.assertEqual(t.name, "lookup")
        self.assertEqual(t.description, "look things up")
        self.assertEqual(t.invoke({"q": 1}), {"found": {"q": 1}})
        self.assertEqual(self.steps()[0]["args"], {"q": 1})
        self.assertEqual(inner.calls, [{"q": 1}])

    def test_blocked_returns_message_without_running(self):
        inner = FakeBaseTool()
        out = rlg.reversible_tool(self.run, "blocked_tool", tool=inner).invoke({"q": 1})
        self.assertIn("tool is not in scope", out)
        self.assertIn("did not run", out)
        self.assertEqual(inner.calls, [])
        self.assertEqual(self.steps(), [])

    def test_pending_approval_id_is_in_the_message(self):
        out = rlg.reversible_tool(self.run, "approve_me")(lambda **kw: 1)(x=1)
        self.assertIn(APPROVAL, out)

    def test_on_block_raise(self):
        f = rlg.reversible_tool(self.run, "approve_me", on_block="raise")(lambda **kw: 1)
        with self.assertRaises(Blocked) as cm:
            f(x=1)
        self.assertEqual(cm.exception.approval_id, APPROVAL)
        with self.assertRaises(ValueError):
            rlg.reversible_tool(self.run, "x", on_block="nope")

    def test_failure_and_uncertainty_are_journaled_and_reraised(self):
        def boom(**kw):
            raise RuntimeError("db down")

        def unsure(**kw):
            raise EffectUncertain("timeout")

        with self.assertRaises(RuntimeError):
            rlg.reversible_tool(self.run, "t1")(boom)()
        with self.assertRaises(EffectUncertain):
            rlg.reversible_tool(self.run, "t2")(unsure)()
        self.assertEqual([s["outcome"]["status"] for s in self.steps()], ["failed", "uncertain"])

    def test_non_json_results_do_not_break_journaling(self):
        obj = object()
        self.assertIs(rlg.reversible_tool(self.run, "t")(lambda: obj)(), obj)

    def test_callable_without_invoke(self):
        class C:
            def __call__(self, x):
                return x + 1
        self.assertEqual(rlg.reversible_tool(self.run, "t", tool=C())(1), 2)


class LangGraphAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_function_and_block(self):
        fake = FakeReversi().start()
        self.addCleanup(fake.stop)
        run = ReversiClient(fake.url, "agent-key").start_run(["p"], run_id="a1")

        @rlg.reversible_tool(run, "alookup")
        async def alookup(x):
            return x * 2

        self.assertEqual(await alookup(3), 6)
        self.assertEqual(fake.runs["a1"]["steps"][0]["outcome"]["status"], "succeeded")
        blocked = rlg.reversible_tool(run, "blocked_x")(alookup)
        self.assertIn("blocked", await blocked(3))


class RollbackNodeTests(unittest.TestCase):
    def test_node_returns_report_in_state(self):
        calls = []

        class FakeRunH:
            def rollback(self, compensate, **kw):
                calls.append(kw)
                return {"complete": True, "compensated": [1]}

        class FakeClient:
            def run(self, rid):
                calls.append(rid)
                return FakeRunH()

        node = rlg.rollback_node(FakeClient(), "run-9", lambda c: None, attempts=2)
        self.assertEqual(node({"messages": []}), {"reversi_rollback": {"complete": True, "compensated": [1]}})
        self.assertEqual(calls, ["run-9", {"attempts": 2}])


class CrewTests(Base):
    class Inner:
        name = "Order lookup"
        description = "finds orders"
        args_schema = None

        def _run(self, order_id):
            return f"order {order_id}"

    def test_journals_and_exposes_crewai_shape(self):
        t = rcrew.ReversibleCrewTool(self.run, "lookup_order", inner=self.Inner())
        self.assertEqual((t.name, t.description), ("Order lookup", "finds orders"))
        self.assertEqual(t._run(order_id="7"), "order 7")
        self.assertEqual(t.run("8"), "order 8")
        self.assertEqual(self.steps()[0]["tool"], "lookup_order")
        self.assertEqual(self.steps()[0]["args"], {"order_id": "7"})

    def test_block_message_and_raise(self):
        t = rcrew.ReversibleCrewTool(self.run, "approve_x", inner=self.Inner())
        self.assertIn(APPROVAL, t._run(order_id="1"))
        t = rcrew.ReversibleCrewTool(self.run, "approve_x", inner=self.Inner(), on_block="raise")
        with self.assertRaises(Blocked):
            t._run(order_id="1")

    def test_to_crewai_builds_subclass_of_real_basetool(self):
        class BaseTool:  # fake crewai.tools.BaseTool
            def run(self, *a, **kw):
                return self._run(*a, **kw)

        mod, tools = types.ModuleType("crewai"), types.ModuleType("crewai.tools")
        tools.BaseTool = BaseTool
        mod.tools = tools
        saved = {k: sys.modules.get(k) for k in ("crewai", "crewai.tools")}
        sys.modules.update({"crewai": mod, "crewai.tools": tools})
        try:
            real = rcrew.ReversibleCrewTool(self.run, "lookup_order", inner=self.Inner()).to_crewai()
        finally:
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        self.assertIsInstance(real, BaseTool)
        self.assertEqual(real.name, "Order lookup")
        self.assertEqual(real.run(order_id="3"), "order 3")
        self.assertEqual(len(self.steps()), 1)


class OpenAIAgentsTests(Base):
    def test_function_wrapper_drops_context_and_journals_json_args(self):
        class RunContextWrapper:
            pass

        @roa.reversi_function_tool(self.run, "create_order")
        def create_order(ctx, sku: str):
            return f"made {sku}"

        self.assertEqual(create_order(RunContextWrapper(), sku="A1"), "made A1")
        self.assertEqual(self.steps()[0]["args"], {"sku": "A1"})

    def test_block_modes_and_error_formatter(self):
        f = roa.reversi_function_tool(self.run, "approve_x")(lambda a: 1)
        self.assertIn(APPROVAL, f({"a": 1}))
        g = roa.reversi_function_tool(self.run, "approve_x", on_block="raise")(lambda a: 1)
        with self.assertRaises(Blocked) as cm:
            g({"a": 1})
        text = roa.tool_error_formatter(None, cm.exception)
        self.assertIn(APPROVAL, text)
        self.assertIn("boom", roa.tool_error_formatter(None, RuntimeError("boom")))

    def test_function_tool_object_is_wrapped(self):
        @dataclasses.dataclass
        class FunctionTool:  # mimics agents.FunctionTool
            name: str
            on_invoke_tool: object

        async def invoke(ctx, input_json):
            return "ok"

        import asyncio
        tool = roa.reversi_function_tool(self.run, "create_order")(FunctionTool("create_order", invoke))
        self.assertEqual(asyncio.run(tool.on_invoke_tool(None, '{"sku": "A1"}')), "ok")
        self.assertEqual(self.steps()[0]["args"], {"sku": "A1"})
        blocked = roa.reversi_function_tool(self.run, "blocked_x")(FunctionTool("x", invoke))
        self.assertIn("blocked", asyncio.run(blocked.on_invoke_tool(None, "{}")))


class GuardrailTests(unittest.IsolatedAsyncioTestCase):
    async def test_trips_when_halted_and_fails_closed(self):
        fake = FakeReversi().start()
        self.addCleanup(fake.stop)
        client = ReversiClient(fake.url, "agent-key", timeout=2)
        g = roa.guardrail(client)
        self.assertFalse((await g(None, None, "hi")).tripwire_triggered)
        fake.halted = True
        r = await g(None, None, "hi")
        self.assertTrue(r.tripwire_triggered)
        self.assertTrue(r.output_info["halted"])
        dead = roa.guardrail(ReversiClient("http://127.0.0.1:9", "k", timeout=1))
        r = await dead(None, None, "hi")
        self.assertTrue(r.tripwire_triggered)
        self.assertIn("could not reach", r.output_info["error"])

    async def test_uses_agents_result_class_when_installed(self):
        class Out:
            def __init__(self, output_info, tripwire_triggered):
                self.output_info, self.tripwire_triggered = output_info, tripwire_triggered

        mod = types.ModuleType("agents")
        mod.GuardrailFunctionOutput = Out
        fake = FakeReversi().start()
        self.addCleanup(fake.stop)
        sys.modules["agents"] = mod
        try:
            r = await roa.guardrail(ReversiClient(fake.url, "agent-key"))(None, None, "x")
        finally:
            del sys.modules["agents"]
        self.assertIsInstance(r, Out)


class FastMCPTests(Base):
    class FakeMCP:  # mimics FastMCP: tool(**kw) returns a decorator
        def __init__(self):
            self.tools = {}

        def tool(self, **kw):
            def deco(fn):
                self.tools[kw.get("name", fn.__name__)] = fn
                return fn
            return deco

    def test_registers_and_journals_with_ctx_passed_to_factory(self):
        mcp, seen = self.FakeMCP(), []

        def factory(ctx):
            seen.append(ctx)
            return self.run

        class Context:
            pass

        @rmcp.reversible(mcp, factory)
        def create_order(sku: str, ctx: Context = None):
            return {"sku": sku}

        ctx = Context()
        self.assertEqual(mcp.tools["create_order"]("A1", ctx=ctx), {"sku": "A1"})
        self.assertEqual(mcp.tools["create_order"]("A2"), {"sku": "A2"})
        self.assertIs(seen[0], ctx)
        self.assertIsNone(seen[1])
        self.assertEqual(self.steps()[0]["args"], {"args": ["A1"], "kwargs": {}})
        self.assertEqual(self.steps()[0]["tool"], "create_order")

    def test_blocked_raises_reversi_blocked_with_approval(self):
        mcp = self.FakeMCP()
        rmcp.reversible(mcp, lambda ctx: self.run, tool_name="approve_refund", name="refund")(lambda amount: amount)
        with self.assertRaises(rmcp.ReversiBlocked) as cm:
            mcp.tools["refund"](amount=5)
        self.assertEqual(cm.exception.approval_id, APPROVAL)
        self.assertIn(APPROVAL, str(cm.exception))
        self.assertEqual(self.steps(), [])

    def test_per_session_runs_reuses_one_run_per_session(self):
        factory = rmcp.per_session_runs(self.client, ["p"], prefix="sess")

        def ctx(session):
            return types.SimpleNamespace(session=session)

        s1, s2 = object(), object()
        a, b, c = factory(ctx(s1)), factory(ctx(s1)), factory(ctx(s2))
        self.assertIs(a, b)
        self.assertNotEqual(a.run_id, c.run_id)
        self.assertTrue(a.run_id.startswith("sess-"))


class FastMCPAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_tool_and_block(self):
        fake = FakeReversi().start()
        self.addCleanup(fake.stop)
        run = ReversiClient(fake.url, "agent-key").start_run(["p"], run_id="m1")

        @rmcp.reversible(None, lambda ctx: run)
        async def read_doc(path: str):
            return path.upper()

        self.assertEqual(await read_doc("a"), "A")
        blocked = rmcp.reversible(None, lambda ctx: run, tool_name="blocked_doc")(read_doc)
        with self.assertRaises(rmcp.ReversiBlocked):
            await blocked("a")


class ImportIsolation(unittest.TestCase):
    def test_core_import_needs_no_framework(self):
        import subprocess
        code = ("import sys, reversi_sdk, reversi_sdk.integrations.langgraph, reversi_sdk.integrations.crewai, "
                "reversi_sdk.integrations.openai_agents, reversi_sdk.integrations.fastmcp, "
                "reversi_sdk.integrations.claude_code_hook;"
                "bad=[m for m in ('langchain','langgraph','crewai','agents','mcp','pydantic') if m in sys.modules];"
                "sys.exit(1 if bad else 0)")
        root = __import__("os").path.abspath(__import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
        r = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
