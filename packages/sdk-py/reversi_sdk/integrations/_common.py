"""Shared plumbing for the adapters: journaled calls, block messages, JSON-safe args."""
from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Dict, Tuple

from ..client import Blocked, EffectUncertain

_CONTEXT_TYPES = {"RunContextWrapper", "ToolContext", "Context", "RunnableConfig"}


def check_on_block(on_block: str) -> str:
    if on_block not in ("message", "raise"):
        raise ValueError('on_block must be "message" or "raise"')
    return on_block


def jsonable(v: Any) -> Any:
    """Round-trip through JSON so the journal never fails on framework objects (they become their repr)."""
    try:
        return json.loads(json.dumps(v, default=repr))
    except (TypeError, ValueError):
        return repr(v)


def journal_args(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
    """What to record as the call's arguments: kwargs, or a single dict positional, without framework contexts."""
    args = tuple(a for a in args if type(a).__name__ not in _CONTEXT_TYPES)
    kwargs = {k: v for k, v in kwargs.items() if type(v).__name__ not in _CONTEXT_TYPES}
    if not args:
        return jsonable(kwargs)
    if len(args) == 1 and not kwargs and isinstance(args[0], dict):
        return jsonable(args[0])
    return jsonable({"args": list(args), "kwargs": kwargs})


def block_message(b: Blocked, tool: str) -> str:
    text = f"Reversi blocked the call to `{tool}`: {'; '.join(b.reasons)}. The tool did not run."
    if b.approval_id:
        text += (f" Approval request {b.approval_id} is pending. Ask an approver to approve it, "
                 "then retry the same call once.")
    return text


def call_sync(run: Any, tool: str, reason: str, fn: Callable[[], Any], args: Any, on_block: str) -> Any:
    holder: list = []

    def execute(_: Any) -> Any:
        r = fn()
        holder.append(r)
        return jsonable(r)

    try:
        run.call(tool, reason, execute, args=args)
    except Blocked as b:
        if on_block == "raise":
            raise
        return block_message(b, tool)
    return holder[0]


async def call_async(run: Any, tool: str, reason: str, fn: Callable[[], Any], args: Any, on_block: str) -> Any:
    """Same journaling as RunHandle.call for a coroutine function; HTTP runs in a worker thread."""
    loop = asyncio.get_running_loop()
    d = await loop.run_in_executor(None, lambda: run.begin(tool, reason, args))
    if d["decision"] == "block":
        b = Blocked(d["reasons"])
        if on_block == "raise":
            raise b
        return block_message(b, tool)
    step = d["step"]

    async def done(status: str, **kw: Any) -> None:
        await loop.run_in_executor(None, lambda: run.complete(step, status, **kw))

    try:
        result = await fn()
    except EffectUncertain as e:
        await done("uncertain", error=str(e)[:300])
        raise
    except Exception as e:
        await done("failed", error=str(e)[:300])
        raise
    await done("succeeded", result=jsonable(result))
    return result
