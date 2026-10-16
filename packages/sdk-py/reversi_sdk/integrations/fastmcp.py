"""FastMCP adapter: make `@mcp.tool()` functions run through a Reversi run (duck-typed on the server object)."""
from __future__ import annotations

import functools
import inspect
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from ..client import Blocked, ReversiClient
from ._common import block_message, call_async, call_sync, journal_args


class ReversiBlocked(Exception):
    """Raised from a tool when Reversi refused the call. FastMCP returns the message to the client as a tool error."""

    def __init__(self, message: str, approval_id: Optional[str] = None, reasons: Optional[List[str]] = None):
        super().__init__(message)
        self.approval_id = approval_id
        self.reasons = reasons or []


def _find_ctx(args: tuple, kwargs: dict) -> Any:
    for k in ("ctx", "context"):
        if k in kwargs:
            return kwargs[k]
    for v in list(kwargs.values()) + list(args):
        if type(v).__name__ == "Context":
            return v
    return None


def _as_blocked(tool: str, e: Blocked) -> ReversiBlocked:
    return ReversiBlocked(block_message(e, tool), e.approval_id, e.reasons)


def reversible(mcp: Any, run_factory: Callable[[Any], Any], reason: str = "MCP tool call",
               tool_name: Optional[str] = None, **tool_kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator replacing `@mcp.tool(**tool_kwargs)`::

        @reversible(mcp, per_session_runs(client, ["orders:write"]))
        def create_order(sku: str) -> dict: ...

    `run_factory(ctx)` returns the RunHandle for this call; ctx is the tool's FastMCP `Context` (a parameter named
    `ctx` or `context`) or None. Pass `mcp=None` to only wrap, without registering. A refusal raises `ReversiBlocked`.
    """
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or fn.__name__
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*a: Any, **kw: Any) -> Any:
                run = run_factory(_find_ctx(a, kw))
                try:
                    return await call_async(run, name, reason, lambda: fn(*a, **kw), journal_args(a, kw), "raise")
                except Blocked as b:
                    raise _as_blocked(name, b) from None
            wrapped: Callable[..., Any] = awrapper
        else:
            @functools.wraps(fn)
            def wrapper(*a: Any, **kw: Any) -> Any:
                run = run_factory(_find_ctx(a, kw))
                try:
                    return call_sync(run, name, reason, lambda: fn(*a, **kw), journal_args(a, kw), "raise")
                except Blocked as b:
                    raise _as_blocked(name, b) from None
            wrapped = wrapper
        if mcp is not None:
            registered = mcp.tool(**tool_kwargs)(wrapped)
            return registered if registered is not None else wrapped
        return wrapped

    return deco


def per_session_runs(client: ReversiClient, permissions: List[str], prefix: str = "mcp") -> Callable[[Any], Any]:
    """A `run_factory` that opens one run per MCP session (keyed by the session object) and reuses it."""
    runs: Dict[Any, Any] = {}
    lock = threading.Lock()

    def factory(ctx: Any) -> Any:
        key: Any = "default"
        if ctx is not None:
            try:
                key = id(ctx.session)
            except Exception:  # noqa: BLE001 - not a real Context: share one run
                key = "default"
        with lock:
            if key not in runs:
                runs[key] = client.start_run(permissions, run_id=f"{prefix}-{uuid.uuid4().hex[:12]}",
                                             reason="MCP session")
            return runs[key]

    return factory
