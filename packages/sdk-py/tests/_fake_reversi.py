"""A tiny in-process fake of the Reversi agent API, enough for the adapters and the Claude Code hook."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

APPROVAL = "apr_0a1b2c-3d"


class FakeReversi:
    """Decisions by tool name: `blocked*` -> block, `approve*` -> pending approval, `would*` -> would_block, else allow."""

    def __init__(self):
        self.runs = {}        # run_id -> {"permissions": [...], "steps": [...]}
        self.requests = []    # (method, path, body)
        self.halted = False
        self.down = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _handle(self, method):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                outer.requests.append((method, self.path, body))
                if self.headers.get("Authorization") != "Bearer agent-key":
                    return self._send(401, {"error": "bad key"})
                parts = self.path.strip("/").split("/")
                if method == "GET" and self.path == "/v1/status":
                    return self._send(200, {"halted": outer.halted})
                if method == "POST" and self.path == "/v1/runs":
                    rid = body.get("run_id") or "gen-1"
                    if rid in outer.runs:
                        return self._send(409, {"error": f"run `{rid}` already exists"})
                    outer.runs[rid] = {"permissions": body["permissions"], "steps": []}
                    return self._send(201, {"run_id": rid, "mode": "enforce"})
                if len(parts) >= 3 and parts[:2] == ["v1", "runs"]:
                    run = outer.runs.get(parts[2])
                    if run is None:
                        return self._send(404, {"error": "run not found"})
                    if method == "GET" and len(parts) == 3:
                        return self._send(200, {"run_id": parts[2], "steps": run["steps"], "unresolved": []})
                    if method == "POST" and parts[3:] == ["intents"]:
                        tool = body["tool"]
                        if tool.startswith("blocked"):
                            return self._send(200, {"decision": "block", "reasons": ["tool is not in scope"]})
                        if tool.startswith("approve"):
                            return self._send(200, {"decision": "block", "reasons": [
                                f"approval required: request {APPROVAL} is pending an operator decision; retry after it is approved"]})
                        step = len(run["steps"])
                        run["steps"].append({"step": step, "tool": tool, "args": body.get("args"), "outcome": None})
                        if tool.startswith("would"):
                            return self._send(200, {"decision": "would_block", "step": step, "reasons": ["dry run"]})
                        return self._send(200, {"decision": "allow", "step": step})
                    if method == "POST" and len(parts) == 6 and parts[3] == "steps" and parts[5] == "outcome":
                        run["steps"][int(parts[4])]["outcome"] = body
                        return self._send(200, {"ok": True})
                self._send(404, {"error": "not found"})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.server = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
