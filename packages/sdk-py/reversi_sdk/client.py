"""HTTP client for the Reversi server (standard library only)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional


class ReversiError(Exception):
    """The server refused or failed a request."""

    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class EffectUncertain(Exception):
    """Raise from a tool to say it is unknown whether the effect happened (timeout, dropped connection)."""


class Blocked(Exception):
    """A call was refused by policy. `reasons` says why. The tool was not executed."""

    def __init__(self, reasons: List[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


class ReversiClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self._key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Any = None, raw: bool = False) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                msg = json.loads(text).get("error", text)
            except ValueError:
                msg = text
            raise ReversiError(e.code, msg) from None
        return text if raw else json.loads(text)

    # --- agent plane ---
    def start_run(self, permissions: List[str], run_id: Optional[str] = None, mode: str = "enforce",
                  reason: Optional[str] = None) -> "RunHandle":
        body: Dict[str, Any] = {"permissions": permissions, "mode": mode}
        if run_id:
            body["run_id"] = run_id
        if reason:
            body["reason"] = reason
        r = self._request("POST", "/v1/runs", body)
        return RunHandle(self, r["run_id"])

    def run(self, run_id: str) -> "RunHandle":
        return RunHandle(self, run_id)

    # --- operator plane ---
    def verify_ledger(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/ledger/verify")


class RunHandle:
    def __init__(self, client: ReversiClient, run_id: str):
        self._c = client
        self.run_id = run_id

    def _p(self, suffix: str = "") -> str:
        return f"/v1/runs/{self.run_id}{suffix}"

    def state(self) -> Dict[str, Any]:
        return self._c._request("GET", self._p())

    def begin(self, tool: str, reason: str, args: Any = None, depends_on: Optional[List[int]] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"tool": tool, "reason": reason}
        if args is not None:
            body["args"] = args
        if depends_on:
            body["depends_on"] = depends_on
        return self._c._request("POST", self._p("/intents"), body)

    def complete(self, step: int, status: str, result: Any = None, error: Optional[str] = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"status": status}
        if result is not None:
            body["result"] = result
        if error:
            body["error"] = error
        return self._c._request("POST", self._p(f"/steps/{step}/outcome"), body)

    def call(self, tool: str, reason: str, execute: Callable[[Any], Any], args: Any = None,
             depends_on: Optional[List[int]] = None) -> Any:
        """Authorize, execute and journal one tool call. Raises Blocked if policy refuses it.

        The intent is journaled before `execute` runs. If the process dies in between, the server
        shows the step as unresolved instead of pretending it never happened.
        """
        d = self.begin(tool, reason, args, depends_on)
        if d["decision"] == "block":
            raise Blocked(d["reasons"])
        step = d["step"]
        try:
            result = execute(args)
        except EffectUncertain as e:
            self.complete(step, "uncertain", error=str(e)[:300])
            raise
        except Exception as e:
            self.complete(step, "failed", error=str(e)[:300])
            raise
        self.complete(step, "succeeded", result=result)
        return result

    # --- operator plane (needs an operator key) ---
    def plan(self) -> Dict[str, Any]:
        return self._c._request("GET", self._p("/plan"))

    def approve(self, tool: str, kind: str = "call", count: int = 1) -> None:
        self._c._request("POST", self._p("/approvals"), {"tool": tool, "kind": kind, "count": count})

    def begin_compensation(self, step: int) -> Dict[str, Any]:
        return self._c._request("POST", self._p(f"/steps/{step}/compensation"), {})

    def complete_compensation(self, step: int, ok: bool, error: Optional[str] = None) -> None:
        body: Dict[str, Any] = {"status": "compensated" if ok else "failed"}
        if error:
            body["error"] = error
        self._c._request("POST", self._p(f"/steps/{step}/compensation/outcome"), body)

    def export_jsonl(self) -> str:
        return self._c._request("GET", self._p("/export"), raw=True)
