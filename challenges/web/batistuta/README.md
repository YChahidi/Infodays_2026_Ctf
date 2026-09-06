# BATISTUTA — Infodays 2026 CTF

**Author:** saamnolimits
**Category:** Web
**Difficulty:** Insane
**Flags:** 2 (user + root), minted fresh per container boot

## Description

Internal scouting platform for the Batistuta squad: a status panel, a small
wiki with pipeline docs, a gophish-style webhook pipeline, a restic backup
endpoint, and two password-gated vaults. Break the whole chain.

## Ports

- `8080/http` — everything (Flask handles all routes).

## Flag format

`infodays{...}` — lowercase. Both flags randomly generated per instance
(see [entrypoint.sh](./entrypoint.sh)) unless operator-overridden via K8s
secrets.

## Solution Overview

See [WRITEUP.md](./WRITEUP.md). End-to-end solver in [solve/solve.py](./solve/solve.py).

Chain:

1. Endpoint/path discovery — `/monitoring/`, `/status/temp`, `/wiki/`.
2. Client-side auth bypass on `/monitoring/` (server always returns
   `{success:false}` but the dashboard has no server-side auth — proxy-flip
   the response *or* just hit `/monitoring/dashboard` directly).
3. `/wiki/n8n` — exported flow JSON leaks `HMAC_SECRET`.
4. `POST /webhook/<uuid>` — HMAC-checked request body; SQLi on `email` with
   error-based echo via the pipeline's "DEBUG" node.
5. Recover `temp.command_log` row 6 (the boot-time timestamp that seeds the
   password generator) via SQLi.
6. `GET /restic/backup.7z` — download the backup.
7. Crack 7z with rockyou (password: `1q2w3e4r5t6y`).
8. Archive contains **user.txt** (user flag), `batistuta-pwgen` ELF, and a
   note pointing at `temp.command_log`.
9. Reverse-engineer the ELF: `srand(sec*1000 + ms); rand() % 62` × 20.
10. Brute-force `ms ∈ [0, 1000)` using the timestamp recovered via SQLi —
    POST each candidate to `/vault/batistuta` until one decrypts the flag.
