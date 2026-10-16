"""HTTP client for the Reversi server (standard library only)."""
from __future__ import annotations

import hashlib
import hmac
import json
import random
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Union


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

    @property
    def approval_id(self) -> Optional[str]:
        """The id of the pending approval request, if the call was blocked waiting for one.

        Ask an approver to decide it, then retry the call: an approval is used exactly once.
        """
        m = re.search(r"request (apr_[0-9a-f-]+) is pending", "; ".join(self.reasons))
        return m.group(1) if m else None


def verify_webhook_signature(secret: Union[str, bytes], body: Union[str, bytes], signature_header: Optional[str]) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    data = body.encode("utf-8") if isinstance(body, str) else body
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.encode("ascii"), signature_header[len("sha256="):].strip().lower().encode("utf-8", "replace"))


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

    @staticmethod
    def verify_webhook_signature(secret: Union[str, bytes], body: Union[str, bytes], signature_header: Optional[str]) -> bool:
        """True if `signature_header` (`sha256=<hex>`) is the HMAC-SHA256 of the raw request body under `secret`.

        Pass the body exactly as received (bytes), before any JSON parsing.
        """
        return verify_webhook_signature(secret, body, signature_header)

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

    # --- read / approver / operator / admin plane (each needs a key with that role) ---
    def verify_ledger(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/ledger/verify")

    def status(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/status")

    def approvals(self, status: Optional[str] = None, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        q = "&".join(f"{k}={v}" for k, v in (("status", status), ("run_id", run_id)) if v)
        return self._request("GET", "/v1/approvals" + (f"?{q}" if q else ""))["approvals"]

    def approve(self, approval_id: str, note: Optional[str] = None) -> Dict[str, Any]:
        return self._request("POST", f"/v1/approvals/{approval_id}/approve", {"note": note} if note else {})

    def deny(self, approval_id: str, note: Optional[str] = None) -> Dict[str, Any]:
        return self._request("POST", f"/v1/approvals/{approval_id}/deny", {"note": note} if note else {})

    def halt(self, reason: str) -> Dict[str, Any]:
        """Kill switch (admin): block every new call until resume()."""
        return self._request("POST", "/v1/halt", {"reason": reason})

    def resume(self) -> Dict[str, Any]:
        return self._request("POST", "/v1/resume", {})

    def ledger_bundle(self) -> Dict[str, Any]:
        """Signed evidence bundle of the whole ledger. Verify it with `reversi verify-bundle`."""
        return self._request("GET", "/v1/ledger/bundle")


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

    def bundle(self) -> Dict[str, Any]:
        return self._c._request("GET", self._p("/bundle"))

    def report_html(self) -> str:
        return self._c._request("GET", self._p("/report"), raw=True)

    def resolve(self, step: int, status: str, note: str, result: Any = None, error: Optional[str] = None) -> Dict[str, Any]:
        """Settle a step whose outcome was unknown, after checking the downstream system (operator)."""
        body: Dict[str, Any] = {"status": status, "note": note}
        if result is not None:
            body["result"] = result
        if error:
            body["error"] = error
        return self._c._request("POST", self._p(f"/steps/{step}/resolve"), body)

    def tool(self, tool: str, reason: str) -> Callable[[Callable[[Any], Any]], Callable[..., Any]]:
        """Decorator: every call to the function goes through this run.

            @run.tool("create_order", "customer asked")
            def create_order(args): ...
            create_order(args={"sku": "A1"})
        """
        def deco(fn: Callable[[Any], Any]) -> Callable[..., Any]:
            def wrapper(args: Any = None, **kw: Any) -> Any:
                return self.call(tool, kw.pop("reason", reason), fn, args=args, **kw)
            wrapper.__name__ = getattr(fn, "__name__", tool)
            return wrapper
        return deco

    def rollback(self, compensate: Callable[[Dict[str, Any]], None], attempts: int = 3, base_delay: float = 0.25,
                 sleep: Callable[[float], None] = time.sleep) -> Dict[str, Any]:
        """Undo the run, newest step first (operator). `compensate(call)` performs one undo and raises on failure.

        Failed compensations are retried with exponential backoff and the same idempotency key
        (`call["idempotency_key"]`: pass it to the downstream API). Returns a report; `complete` is True
        only if nothing was left undone or unexplained.
        """
        report: Dict[str, Any] = {"compensated": [], "failed": [], "deferred": [], "awaiting_approval": [],
                                  "not_undoable": [], "complete": False}
        for step in sorted((s["step"] for s in self.state()["steps"]), reverse=True):
            start = self.begin_compensation(step)
            d = start["decision"]
            if d == "go":
                err: Optional[str] = None
                for attempt in range(1, max(1, attempts) + 1):
                    try:
                        compensate(start["call"])
                        err = None
                        break
                    except Exception as e:  # noqa: BLE001 - any failure of the undo is reported, not hidden
                        err = str(e)[:300]
                        if attempt < attempts:
                            sleep(min(5.0, base_delay * 2 ** (attempt - 1)) * (0.5 + random.random() / 2))
                if err is None:
                    self.complete_compensation(step, ok=True)
                    report["compensated"].append(step)
                else:
                    self.complete_compensation(step, ok=False, error=err)
                    report["failed"].append({"step": step, "error": err})
            elif d == "defer":
                report["deferred"].append(step)
            elif d == "awaiting_approval":
                report["awaiting_approval"].append(step)
            elif d == "not_actionable" and start.get("kind") != "skip":
                report["not_undoable"].append({"step": step, "kind": start.get("kind"), "note": start.get("note")})
        report["complete"] = not (report["failed"] or report["deferred"] or report["awaiting_approval"] or report["not_undoable"])
        return report
