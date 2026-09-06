# referee_briefing

**Category:** LLM / MCP Security
**Difficulty:** Two-flag challenge — Medium (user) and Hard (root)
**Type:** Network service (Docker container, port 8008)

## Player brief

> The Infodays 2026 referee crew runs a local MCP server that
> exposes three tools for use during live matches: `list_reports`,
> `read_report`, and `match_stats`. The server was built in a hurry
> for the tournament and has not been security-reviewed.
>
> Speak the MCP protocol to the server, break it open, and extract
> both flags:
>
> - **User flag** lives in `/app/secrets/user_flag.txt`, owned by
>   the `referee` user that runs the server. Not advertised by
>   `list_reports()`.
> - **Root flag** lives in `/root/root_flag.txt`, mode 600,
>   root-owned. You'll need to escalate.
>
> **Target:** `nc` / `curl` / any HTTP client → `POST /mcp` on port
> 8008 with JSON-RPC 2.0 bodies.
>
> **Flag format:** `INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## What is MCP?

The [Model Context Protocol](https://modelcontextprotocol.io) is
the emerging standard that LLM runtimes use to talk to tool
servers. An MCP server exposes:

- **Tools** — callable functions with a JSON schema
- **Resources** — readable content blobs
- **Prompts** — pre-canned templates

MCP is [JSON-RPC 2.0](https://www.jsonrpc.org/specification) at the
wire level. The referee server implements the three methods you
need for this challenge:

```
POST /mcp
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"...","arguments":{...}}}
```

An LLM is *not* required to solve this — players talk to the MCP
server directly with any HTTP client. The "LLM security" angle is
that MCP servers frequently ship with permissive tool
implementations because the designers assumed only a "friendly
LLM" would ever call them. That assumption does not survive a
CTF.

## Difficulty breakdown

| # | Flag | Difficulty | Vector |
|---|------|------------|--------|
| 1 | user | Medium     | Path traversal in a poorly-written MCP tool |
| 2 | root | Hard       | Python `eval` sandbox escape → RCE → suid `find` privesc |

### Flag 1 — Medium (user)

Read `server.py`. The `read_report` tool does `open(f"/app/reports/{name}")`
with no sanitisation. A name of `"../secrets/user_flag.txt"` walks
right out of the reports directory. Call it via MCP, parse the
content, done.

### Flag 2 — Hard (root)

Read `server.py` harder. The `match_stats` tool calls `eval` with
`{"__builtins__": {}}` — the classic "I cleared builtins so this
is safe" pattern, which has been broken since Python 2. Reach
`os._wrap_close` through `().__class__.__mro__[-1].__subclasses__()`,
pull `os.popen` out of its `__init__.__globals__`, and you have a
shell call primitive.

That gives you RCE as the `referee` user inside the container. The
root flag is 600 / root-owned, so you still need to escalate. Run
`find / -perm -u=s 2>/dev/null` — `/usr/bin/find` is setuid root.
From [GTFOBins](https://gtfobins.github.io/gtfobins/find/):

```
find . -exec cat /root/root_flag.txt \;
```

`find` forks `cat` with its inherited EUID=0, `cat` reads the
root-only file, done.

## Deployment

```bash
# 1. Rotate flags (populates .env and flag.txt)
python3 gen.py

# 2. Build + run the container
docker compose up -d --build

# 3. Confirm the server is listening
curl -s http://localhost:8008/health
# {"name":"infodays-var-referee-briefing",...}

# 4. Hand players the host:port. They can speak MCP directly.
```

## Files

| Path | Purpose |
|------|---------|
| `server/server.py` | MCP server (vulnerable) |
| `server/reports/*.md` | Sample referee reports — player-visible |
| `Dockerfile` | Build: installs flags, sets suid find, runs server as referee |
| `docker-compose.yml` | Standalone service definition |
| `entrypoint.sh` | Writes flags from env vars, drops to referee, starts server |
| `gen.py` | Rotates flag hex suffix, writes `.env` + `flag.txt` |
| `solver/solve.py` | Full exploit chain (both flags, pure stdlib) |
| `flag.txt` | Current build's flags (author-side) |

## Current flags

Regenerate with `python3 gen.py` before publishing. See `flag.txt`.

## Requirements

- Docker / Docker Compose
- Players: any HTTP client (curl, Python `urllib`, MCP Inspector,
  or a real MCP client SDK)
