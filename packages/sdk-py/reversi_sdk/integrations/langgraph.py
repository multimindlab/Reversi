"""LangChain / LangGraph adapter (duck-typed: no langchain import is needed)."""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict

from ._common import call_async, call_sync, check_on_block, journal_args


class _ReversibleTool:
    """Proxy for a BaseTool-like object: `.name`, `.invoke(input)` (or callable). Other attributes pass through."""

    def __init__(self, run: Any, tool_name: str, reason: str, on_block: str, target: Any):
        self._run = run
        self._tool_name = tool_name
        self._reason = reason
        self._on_block = on_block
        self._target = target

    def __getattr__(self, item: str) -> Any:
        return getattr(self._target, item)

    def invoke(self, input: Any, *a: Any, **kw: Any) -> Any:
        fn = self._target.invoke if hasattr(self._target, "invoke") else self._target
        return call_sync(self._run, self._tool_name, self._reason, lambda: fn(input, *a, **kw),
                         journal_args((input,), {}), self._on_block)

    async def ainvoke(self, input: Any, *a: Any, **kw: Any) -> Any:
        if hasattr(self._target, "ainvoke"):
            fn = self._target.ainvoke
            return await call_async(self._run, self._tool_name, self._reason, lambda: fn(input, *a, **kw),
                                    journal_args((input,), {}), self._on_block)
        return self.invoke(input, *a, **kw)

    def __call__(self, *a: Any, **kw: Any) -> Any:
        if hasattr(self._target, "invoke") and len(a) == 1 and not kw:
            return self.invoke(a[0])
        return call_sync(self._run, self._tool_name, self._reason, lambda: self._target(*a, **kw),
                         journal_args(a, kw), self._on_block)


def reversible_tool(run: Any, tool_name: str, reason: str = "agent tool call", on_block: str = "message",
                    tool: Any = None) -> Any:
    """Route every call of a tool through `run.call`.

    Use as a decorator on the plain function, *before* `@tool` so LangChain still sees the signature::

        @tool
        @reversible_tool(run, "create_order", reason="customer asked")
        def create_order(sku: str) -> dict: ...

    or wrap an existing BaseTool-like object (`reversible_tool(run, "x")(my_tool)`, or pass `tool=`).
    A blocked call returns an explanatory string (`on_block="message"`) or raises `Blocked` (`on_block="raise"`).
    """
    check_on_block(on_block)

    def wrap(target: Any) -> Any:
        if hasattr(target, "invoke") or not callable(target):
            return _ReversibleTool(run, tool_name, reason, on_block, target)
        if inspect.iscoroutinefunction(target):
            @functools.wraps(target)
            async def awrapper(*a: Any, **kw: Any) -> Any:
                return await call_async(run, tool_name, reason, lambda: target(*a, **kw), journal_args(a, kw), on_block)
            return awrapper

        @functools.wraps(target)
        def wrapper(*a: Any, **kw: Any) -> Any:
            return call_sync(run, tool_name, reason, lambda: target(*a, **kw), journal_args(a, kw), on_block)
        return wrapper

    return wrap(tool) if tool is not None else wrap


def rollback_node(client: Any, run_id: str, compensate: Callable[[Dict[str, Any]], None],
                  state_key: str = "reversi_rollback", **rollback_kwargs: Any) -> Callable[[Any], Dict[str, Any]]:
    """A LangGraph node that undoes the run (operator key needed). Returns `{state_key: report}`."""
    def node(state: Any = None) -> Dict[str, Any]:
        return {state_key: client.run(run_id).rollback(compensate, **rollback_kwargs)}
    node.__name__ = "reversi_rollback"
    return node
