#!/usr/bin/env python3
"""
Infodays 2026 — VAR Referee Briefing MCP Server.

A lightweight MCP-compatible JSON-RPC 2.0 server over HTTP. Exposes
three tools the referee crew uses during live matches to consult
briefings and compute quick match stats. The implementation was
written in a hurry for the tournament and does not have a security
review.

MCP methods implemented:

    POST /mcp   body = {"jsonrpc":"2.0","id":N,"method":...,"params":...}

    initialize             -> server info + protocol version
    tools/list             -> list of available tools
    tools/call             -> invoke a tool, returns MCP content[]
    ping                   -> {}

Tools:

    list_reports()                              -> list .md files in /app/reports
    read_report(name)                           -> return file contents
    match_stats(expression)                     -> eval a stats formula
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/app/reports"))

TOOLS = [
    {
        "name": "list_reports",
        "description": (
            "List all match-briefing reports currently available in the "
            "referee folder."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "read_report",
        "description": (
            "Read a named match-briefing report. The `name` argument is a "
            "filename inside the referee report folder (e.g. "
            "`group_stage_day_1.md`)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Report filename (not an absolute path).",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "match_stats",
        "description": (
            "Evaluate a match-statistics formula over the current match. "
            "The formula is a Python expression that may reference any of "
            "the following named metrics: home_goals, away_goals, corners, "
            "fouls, pass_accuracy, possession_home, possession_away, "
            "shots_home, shots_away, yellow_cards, red_cards. Example: "
            "'home_goals - away_goals' or 'pass_accuracy * 100'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "A Python math expression over match metrics.",
                },
            },
            "required": ["expression"],
        },
    },
]

MATCH_METRICS = {
    "home_goals": 2,
    "away_goals": 1,
    "corners": 8,
    "fouls": 14,
    "pass_accuracy": 0.82,
    "possession_home": 57,
    "possession_away": 43,
    "shots_home": 12,
    "shots_away": 9,
    "yellow_cards": 3,
    "red_cards": 0,
}


def _ok(text: str, is_error: bool = False) -> dict:
    out = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


def tool_list_reports(_: dict) -> dict:
    if not REPORTS_DIR.is_dir():
        return _ok(f"reports directory missing: {REPORTS_DIR}", is_error=True)
    names = sorted(p.name for p in REPORTS_DIR.glob("*.md"))
    return _ok("\n".join(names) if names else "(no reports)")


def tool_read_report(args: dict) -> dict:
    name = args.get("name", "")
    if not isinstance(name, str) or not name:
        return _ok("name must be a non-empty string", is_error=True)
    # The referee's reports live under /app/reports. We join the requested
    # filename onto that directory and open it. Simple and direct.
    path = f"{REPORTS_DIR}/{name}"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return _ok(f"no such report: {name}", is_error=True)
    except PermissionError:
        return _ok(f"permission denied: {name}", is_error=True)
    except OSError as exc:
        return _ok(f"read error: {exc}", is_error=True)
    return _ok(text)


def tool_match_stats(args: dict) -> dict:
    expression = args.get("expression", "")
    if not isinstance(expression, str) or not expression:
        return _ok("expression must be a non-empty string", is_error=True)
    # "Sandboxed" eval: we blank out __builtins__ and only expose the
    # match metrics as locals. This prevents the expression from
    # calling print(), open(), import, etc — it can only do arithmetic
    # on the whitelisted names.
    try:
        result = eval(expression, {"__builtins__": {}}, dict(MATCH_METRICS))
    except Exception as exc:
        return _ok(f"eval error: {exc}", is_error=True)
    return _ok(f"result = {result}")


TOOL_IMPL = {
    "list_reports": tool_list_reports,
    "read_report": tool_read_report,
    "match_stats": tool_match_stats,
}


def handle_initialize(_: dict) -> dict:
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {
            "name": "infodays-var-referee-briefing",
            "version": "1.0.0",
        },
    }


def handle_tools_list(_: dict) -> dict:
    return {"tools": TOOLS}


def handle_tools_call(params: dict) -> dict:
    name = params.get("name", "")
    args = params.get("arguments", {}) or {}
    impl = TOOL_IMPL.get(name)
    if impl is None:
        return _ok(f"unknown tool: {name}", is_error=True)
    return impl(args)


HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "ping": lambda _: {},
    "notifications/initialized": lambda _: None,
}


class MCPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/health"):
            self._send_json(200, {
                "name": "infodays-var-referee-briefing",
                "protocol": "mcp/jsonrpc-2.0",
                "endpoint": "POST /mcp",
            })
            return
        self.send_error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        try:
            req = json.loads(body)
        except Exception:
            self._send_json(400, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            })
            return

        method = req.get("method", "")
        params = req.get("params", {}) or {}
        req_id = req.get("id")
        handler = HANDLERS.get(method)

        if handler is None:
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            })
            return

        try:
            result = handler(params)
        except Exception as exc:
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": f"internal error: {exc}"},
            })
            return

        if result is None:
            self.send_response(202)
            self.end_headers()
            return

        self._send_json(200, {"jsonrpc": "2.0", "id": req_id, "result": result})

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write(f"[mcp] {fmt % args}\n")


def main() -> int:
    port = int(os.environ.get("PORT", "8008"))
    server = ThreadingHTTPServer(("0.0.0.0", port), MCPHandler)
    print(f"[mcp] listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
