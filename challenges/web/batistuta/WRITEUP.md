# BATISTUTA — Writeup

**Author:** saamnolimits
**Category:** Web
**Difficulty:** Insane
**Flags:** 2 (user + root), regenerated per container boot.

## Stage 0 — Recon

Landing page at `/` links to:

- `/monitoring/` — status panel (login page)
- `/wiki/` — internal wiki
- mentions of a GoPhish-style webhook pipeline.

A quick directory sweep finds the monitoring app is a simple login form. The
wiki has a "phishing pipeline" entry.

## Stage 1 — Client-side auth bypass on /monitoring/

The login UI POSTs `{username, password}` to `/monitoring/api/login`. The
server always returns `{"success": false, "reason": "invalid credentials"}`.
The JavaScript only redirects if `success === true`.

Two ways in:

1. **Proxy intercept / flip** — catch the response and change `false` → `true`.
   The client redirects to `/monitoring/dashboard`, which has **no server-side
   auth check** and renders happily.
2. **Direct request** — just `GET /monitoring/dashboard`. Same outcome.

The dashboard links to `/status/temp`, which lists the webhook UUID
(`d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d`), the restic endpoint, and the vaults.

## Stage 2 — Wiki leaks the HMAC signing secret

`GET /wiki/n8n` renders an exported "flow" JSON describing the pipeline. The
`Calculate the signature` node embeds the secret in plaintext:

```json
{
  "name": "Calculate the signature",
  "parameters": {
    "action": "hmac", "type": "SHA256",
    "value": "={{ JSON.stringify($json.body) }}",
    "secret": "<the secret>"
  }
}
```

The HTML HTML-escapes the JSON so the solver unescapes entities before
pattern-matching.

## Stage 3 — HMAC-signed SQLi via JSON body

The webhook checks `x-gophish-signature: sha256=<hex>` against
`HMAC-SHA256(secret, JSON.stringify(body))`. JSON is normalized with
`separators=(',', ':')` — no whitespace — to match the Node.js semantics.

With a valid signature, the backend interpolates `email` straight into the
SQL:

```python
sql = f'SELECT * FROM victims where email = "{email}" LIMIT 1'
```

`MULTI_STATEMENTS` is on, and when the query errors out the app echoes the
failure back to the caller (the "DEBUG: REMOVE SOON" pipeline node). That
error echo is the exfil channel — classic error-based SQLi via
`UPDATEXML(1, CONCAT(0x7e, (SELECT …)), 1)`.

Payload template (hex-friendly delimiter `~`):

```
{"campaign_id":1,
 "email":"x\" AND updatexml(1, CONCAT(0x7e, (SELECT <expr>)), 1)-- -",
 "message":"Clicked Link"}
```

Resign, POST, parse `~<value>` out of the returned XPATH syntax error.

Recover `DATABASE()` → smoke test, then:

```sql
SELECT date    FROM temp.command_log WHERE id = 6  -- boot-time timestamp
SELECT command FROM temp.command_log WHERE id = 6
```

The timestamp is the seed for the stage-2 password generator.

## Stage 4 — Restic backup download + 7z crack

`GET /restic/backup.7z` serves the boot-time archive (no auth — the
"credentials" in `temp.command_log` are narrative only). The archive uses
7-Zip with header encryption; a single rockyou-style candidate cracks it:

```
1q2w3e4r5t6y
```

Inside:

- `user.txt` — **the user flag.**
- `batistuta-pwgen` — an ELF.
- `note.txt` — pointer to `temp.command_log` for the timestamp.

## Stage 5 — Reverse-engineer batistuta-pwgen

The C source compiled at build time:

```c
gettimeofday(&tv, NULL);
srand(tv.tv_sec * 1000 + tv.tv_usec / 1000);
for (int i = 0; i < 20; i++)
    pw[i] = CHARSET[rand() % 62];
```

Ghidra will show this. The seed is `epoch_seconds * 1000 + millis`. The
attacker has recovered the `YYYY-MM-DD HH:MM:SS` second from SQLi — only the
ms offset (0–999) is unknown.

## Stage 6 — Brute force millisecond + submit to /vault/batistuta

Reproduce libc's `rand()` from Python using `ctypes.CDLL("libc.so.6")` —
Python's PRNG is NOT compatible. Generate 1 000 candidate passwords for
`ms ∈ [0, 1000)` and POST each to `/vault/batistuta`. The server attempts to
decrypt `root.txt.enc` (AES-256-CBC + PBKDF2) with the submitted password;
one hit returns the **root flag**.

Timezone note: the DB column is naive; interpret as UTC (the entrypoint uses
`date -u`). The solver tries both UTC and local interpretations for
robustness.

## Why this fits the K8s posture

Identical constraints to every challenge on the platform:

```yaml
runAsUser: 1000
runAsNonRoot: true
allowPrivilegeEscalation: false
capabilities: { drop: ["ALL"] }
```

All processes share UID 1000 in the pod. To gate the flags despite the
attacker reading `/proc/*/environ` after hypothetical RCE:

- `root.txt` is **never** plaintext on disk after entrypoint runs — only
  `root.txt.enc` exists, encrypted with the timestamp-seeded password.
- The plaintext `FLAG2` is scrubbed from env via `unset` before spawning
  supervisord, so `/proc/<pid>/environ` of every service is clean.
- The Flask process knows only `FLAG2_ENC_B64` and calls `openssl enc -d`
  when it receives a candidate password — identical flow to how a real
  admin would decrypt the flag file after cracking the pwgen output.
