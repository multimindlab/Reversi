"""OpenAI Agents SDK adapter (duck-typed; the `agents` package is imported lazily, only by `guardrail`)."""
from __future__ import annotations

import asyncio
import dataclasses
import functools
import inspect
import json
from typing import Any, Callable

from ..client import Blocked, ReversiClient
from ._common import block_message, call_async, call_sync, check_on_block, journal_args


def reversi_function_tool(run: Any, tool_name: str, reason: str = "agent tool call",
                          on_block: str = "message") -> Callable[[Any], Any]:
    """Wrap the function you pass to `@function_tool` (put this decorator *under* it)::

        @function_tool
        @reversi_function_tool(run, "create_order")
        def create_order(sku: str) -> str: ...

    It also accepts a ready `FunctionTool` (it wraps `on_invoke_tool(ctx, input_json)`).
    Use `on_block="raise"` with `tool_error_formatter` to let the SDK turn a block into model-visible text.
    """
    check_on_block(on_block)

    def deco(target: Any) -> Any:
        if hasattr(target, "on_invoke_tool"):
            inner = target.on_invoke_tool

            async def on_invoke(ctx: Any, input_json: str) -> Any:
                try:
                    args = json.loads(input_json) if input_json else {}
                except ValueError:
                    args = {"raw": input_json}
                return await call_async(run, tool_name, reason, lambda: inner(ctx, input_json), args, on_block)

            if dataclasses.is_dataclass(target):
                return dataclasses.replace(target, on_invoke_tool=on_invoke)
            target.on_invoke_tool = on_invoke
            return target
        if inspect.iscoroutinefunction(target):
            @functools.wraps(target)
            async def awrapper(*a: Any, **kw: Any) -> Any:
                return await call_async(run, tool_name, reason, lambda: target(*a, **kw), journal_args(a, kw), on_block)
            return awrapper

        @functools.wraps(target)
        def wrapper(*a: Any, **kw: Any) -> Any:
            return call_sync(run, tool_name, reason, lambda: target(*a, **kw), journal_args(a, kw), on_block)
        return wrapper

    return deco


def tool_error_formatter(ctx: Any, error: Exception) -> str:
    """For `function_tool(failure_error_function=...)`: a `Blocked` becomes an instruction to the model, not a crash."""
    if isinstance(error, Blocked):
        return block_message(error, "this tool")
    return f"An error occurred while running the tool: {error}"


class GuardrailResult:
    """Stand-in for `agents.GuardrailFunctionOutput` when the package is not installed."""

    def __init__(self, output_info: Any, tripwire_triggered: bool):
        self.output_info = output_info
        self.tripwire_triggered = tripwire_triggered


def guardrail(client: ReversiClient, run: Any = None) -> Callable[..., Any]:
    """Input guardrail that trips while the Reversi kill switch is on (the key must be allowed to read `/v1/status`)::

        Agent(..., input_guardrails=[InputGuardrail(guardrail_function=guardrail(client, run))])

    If Reversi cannot be reached the guardrail trips (fails closed).
    """
    async def reversi_kill_switch(ctx: Any = None, agent: Any = None, input: Any = None) -> Any:
        try:
            st = await asyncio.get_running_loop().run_in_executor(None, client.status)
            halted = bool(st.get("halted"))
            info = {"halted": halted, "run_id": getattr(run, "run_id", None)}
        except Exception as e:  # noqa: BLE001
            halted, info = True, {"error": f"could not reach Reversi: {e}"}
        try:
            from agents import GuardrailFunctionOutput  # type: ignore[import-not-found]
        except ImportError:
            return GuardrailResult(info, halted)
        return GuardrailFunctionOutput(output_info=info, tripwire_triggered=halted)

    return reversi_kill_switch
