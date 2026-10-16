"""Claude Code PreToolUse / PostToolUse hook backed by a Reversi run per Claude session.

Pre:  `reversi-claude-hook`         reads the hook JSON on stdin, asks Reversi, prints the permission decision.
Post: `reversi-claude-hook --post`  reports the outcome of the step recorded at Pre time.

Environment: REVERSI_URL, REVERSI_AGENT_KEY, REVERSI_PERMISSIONS (comma list), REVERSI_HOOK_FAIL_OPEN=1,
REVERSI_HOOK_STATE (state directory), REVERSI_TIMEOUT (seconds, default 5).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from typing import Any, Dict, Mapping, Optional, TextIO

from ..client import ReversiClient, ReversiError, Blocked


def map_tool_name(name: str) -> str:
    """`mcp__server__tool` becomes `server.tool`; every other name is used as is."""
    m = re.fullmatch(r"mcp__(.+?)__(.+)", name)
    return f"{m.group(1)}.{m.group(2)}" if m else name


def _state_dir(env: Mapping[str, str]) -> str:
    d = env.get("REVERSI_HOOK_STATE") or os.path.join(tempfile.gettempdir(), "reversi-claude-hook")
    os.makedirs(d, exist_ok=True)
    return d


def _state_path(env: Mapping[str, str], session_id: str) -> str:
    return os.path.join(_state_dir(env), re.sub(r"[^A-Za-z0-9_-]", "_", session_id) + ".json")


def _call_key(hook: Dict[str, Any]) -> str:
    tid = hook.get("tool_use_id")
    if isinstance(tid, str) and tid:
        return tid
    digest = hashlib.sha256(json.dumps(hook.get("tool_input"), sort_keys=True, default=repr).encode()).hexdigest()[:16]
    return f"{hook.get('tool_name')}:{digest}"


def _load(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(path: str, data: Dict[str, Any]) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _decision(kind: str, reason: str) -> Dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind,
                                   "permissionDecisionReason": reason}}


def _client(env: Mapping[str, str]) -> ReversiClient:
    url, key = env.get("REVERSI_URL"), env.get("REVERSI_AGENT_KEY")
    if not url or not key:
        raise RuntimeError("REVERSI_URL and REVERSI_AGENT_KEY must be set")
    return ReversiClient(url, key, timeout=float(env.get("REVERSI_TIMEOUT") or 5))


def _ensure_run(client: ReversiClient, run_id: str, env: Mapping[str, str]) -> Any:
    run = client.run(run_id)
    try:
        run.state()
        return run
    except ReversiError as e:
        if e.status != 404:
            raise
    perms = [p.strip() for p in (env.get("REVERSI_PERMISSIONS") or "").split(",") if p.strip()]
    try:
        return client.start_run(perms, run_id=run_id, reason="Claude Code session")
    except ReversiError as e:
        if e.status == 409:  # another hook process opened it first
            return run
        raise


def pre_tool_use(hook: Dict[str, Any], env: Mapping[str, str]) -> Dict[str, Any]:
    fail_open = env.get("REVERSI_HOOK_FAIL_OPEN") == "1"
    try:
        session = str(hook.get("session_id") or "")
        tool_name = hook.get("tool_name")
        if not session or not isinstance(tool_name, str):
            raise ValueError("hook input needs session_id and tool_name")
        tool_input = hook.get("tool_input")
        run = _ensure_run(_client(env), f"claude-{session}", env)
        tool = map_tool_name(tool_name)
        reason = ""
        if isinstance(tool_input, dict) and isinstance(tool_input.get("description"), str):
            reason = tool_input["description"]
        d = run.begin(tool, (reason or f"Claude Code called {tool_name}")[:200], tool_input)
    except Exception as e:  # noqa: BLE001 - anything wrong means Reversi could not vouch for the call
        if fail_open:
            return _decision("allow", f"Reversi unavailable ({e}); REVERSI_HOOK_FAIL_OPEN=1 so the call is allowed unrecorded")
        return _decision("deny", f"Reversi unavailable ({e}); failing closed")

    if d["decision"] in ("allow", "would_block"):
        path = _state_path(env, session)
        state = _load(path)
        state[_call_key(hook)] = d["step"]
        _save(path, state)
        note = "; ".join(d.get("reasons", []))
        return _decision("allow", f"Reversi step {d['step']}" + (f" (would block: {note})" if note else ""))
    b = Blocked(d.get("reasons", []))
    if b.approval_id:
        return _decision("ask", f"Reversi requires approval: request {b.approval_id} is pending. "
                                f"Have a Reversi approver approve it, then retry. ({'; '.join(b.reasons)})")
    return _decision("deny", "Reversi blocked this call: " + "; ".join(b.reasons))


def post_tool_use(hook: Dict[str, Any], env: Mapping[str, str]) -> Optional[str]:
    """Report the outcome for the step recorded at Pre time. Returns a message for stderr on trouble, else None."""
    session = str(hook.get("session_id") or "")
    if not session:
        return "no session_id"
    path = _state_path(env, session)
    state = _load(path)
    key = _call_key(hook)
    if key not in state:
        return None  # no Pre record (allowed by Claude Code's own prompt, or the hook was not installed then)
    step = state[key]
    resp = hook.get("tool_response")
    failed = hook.get("hook_event_name") == "PostToolUseFailure" or (
        isinstance(resp, dict) and (resp.get("is_error") is True or bool(resp.get("error"))))
    run = _client(env).run(f"claude-{session}")
    if failed:
        err = hook.get("error") or (resp.get("error") if isinstance(resp, dict) else None) or "tool failed"
        run.complete(step, "failed", error=str(err)[:300])
    else:
        small = isinstance(resp, dict) and len(json.dumps(resp, default=repr)) < 100_000
        run.complete(step, "succeeded", result=resp if small else None)
    del state[key]
    _save(path, state)
    return None


def main(argv: Optional[list] = None, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None,
         env: Optional[Mapping[str, str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin, stdout, env = stdin or sys.stdin, stdout or sys.stdout, os.environ if env is None else env
    post = "--post" in argv
    try:
        hook = json.loads(stdin.read())
        if not isinstance(hook, dict):
            raise ValueError("hook input must be a JSON object")
    except ValueError as e:
        if not post:
            stdout.write(json.dumps(_decision("deny", f"unreadable hook input: {e}")) + "\n")
        else:
            sys.stderr.write(f"reversi-claude-hook: unreadable hook input: {e}\n")
        return 0
    if post:
        try:
            msg = post_tool_use(hook, env)
        except Exception as e:  # noqa: BLE001 - the tool already ran; never fail the session over reporting
            msg = str(e)
        if msg:
            sys.stderr.write(f"reversi-claude-hook: could not report outcome: {msg}\n")
        return 0
    stdout.write(json.dumps(pre_tool_use(hook, env)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
