"""CrewAI adapter, duck-typed on `crewai.tools.BaseTool` (`name`, `description`, `_run`)."""
from __future__ import annotations

from typing import Any, Optional

from ._common import call_sync, check_on_block, journal_args


class ReversibleCrewTool:
    """Journals every `_run` through a Reversi run.

    Wrap an existing tool (anything with `_run` or `run`), or subclass and override `_execute`::

        tool = ReversibleCrewTool(run, "lookup_order", inner=MyCrewTool(), reason="support ticket")
        agent = Agent(..., tools=[tool.to_crewai()])
    """

    def __init__(self, run: Any, tool_name: str, inner: Any = None, name: Optional[str] = None,
                 description: Optional[str] = None, reason: str = "agent tool call", on_block: str = "message"):
        self.run_handle = run
        self.tool_name = tool_name
        self.inner = inner
        self.name = name or getattr(inner, "name", tool_name)
        self.description = description or getattr(inner, "description", "")
        self.args_schema = getattr(inner, "args_schema", None)
        self.reason = reason
        self.on_block = check_on_block(on_block)

    def _execute(self, *args: Any, **kwargs: Any) -> Any:
        if self.inner is None:
            raise NotImplementedError("pass inner=... or override _execute")
        fn = getattr(self.inner, "_run", None) or self.inner.run
        return fn(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return call_sync(self.run_handle, self.tool_name, self.reason, lambda: self._execute(*args, **kwargs),
                         journal_args(args, kwargs), self.on_block)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def to_crewai(self) -> Any:
        """Build a real `crewai.tools.BaseTool` that delegates to this adapter (imports crewai lazily)."""
        from crewai.tools import BaseTool  # type: ignore[import-not-found]

        outer = self
        attrs = {"__annotations__": {"name": str, "description": str},
                 "name": self.name, "description": self.description,
                 "_run": lambda s, *a, **kw: outer._run(*a, **kw)}
        if self.args_schema is not None:
            attrs["__annotations__"]["args_schema"] = type(self.args_schema)
            attrs["args_schema"] = self.args_schema
        return type("Reversible" + "".join(c for c in self.name.title() if c.isalnum()), (BaseTool,), attrs)()
