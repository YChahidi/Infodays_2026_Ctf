# YAMI SUKEHIRO — Infodays 2026 CTF

**Author:** saamnolimits
**Category:** Web
**Difficulty:** Hard
**Flags:** 2 (user + root), minted fresh per container boot

## Description

Captain Yami Sukehiro of the Black Bulls has launched an online mana-channeling
reservation system for the squad. Rumor says the backend is held together with
dark magic and duct tape. Find both flags.

- User flag: `/flags/user.txt` inside the container.
- Root flag: `/flags/root.txt.enc` (encrypted) inside the container.

## Ports

- `8080/http` — mana reservation site.

## Flag format

`infodays{...}` — lowercase. Both flags are randomly generated per instance
(see [entrypoint.sh](./entrypoint.sh)) unless operator-overridden via K8s
secrets.

## Solution Overview

See [WRITEUP.md](./WRITEUP.md). End-to-end solver in [solve/solve.py](./solve/solve.py).

Chain:

1. Stateful directory traversal via `/reminder/<id>` → `/export/<traversal>`.
2. Leak Flask source, notice weak RSA in `config/signature.py` (q ≈ 2²⁰).
3. Factor JWT's `n`, forge a JWT with `role: captain`.
4. Captain dashboard has stacked-query SQLi (`order by ... ${o}`).
5. MySQL `FILE` privilege → `SELECT ... INTO DUMPFILE '/data/scripts/fixer-v<tag>.sh'`.
6. In-container cron simulator executes the newest `fixer-v*` within 60 s → RCE,
   read user flag.
7. Same RCE runs `hg cat -r 0 config.py` in `/opt/hg_repo` — first commit
   contains `CAPTAIN_SECRET`.
8. Decrypt `/flags/root.txt.enc` with `openssl enc -aes-256-cbc -d -pbkdf2
   -pass pass:$CAPTAIN_SECRET` → root flag.
