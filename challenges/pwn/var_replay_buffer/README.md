# VAR Replay Buffer

**Category:** pwn
**Difficulty:** mid-hard
**Port:** 8011

> The Moroccan Football Federation has rolled out a new VAR Replay Buffer
> for InfoDays 2026. Only "verified officials" get to compress raw feeds.
> Rumor is the head referee left his private verdict routine compiled in.
> Find it.

## For players

You get:

- `var_replay_buffer` — a stripped 64-bit ELF with full mitigations.
- `gccparams.txt` — the build flags used.

You do **not** get the source. Reverse engineer it.

Connect with:

```
nc <host> 8011
```

Flag format: `INFODAYS{...}`

## For the organizer

Source, Dockerfile, and a reference exploit live in this directory. Ship
**only** `var_replay_buffer` (and optionally `gccparams.txt`) to players.

Build and run locally:

```
docker compose up -d --build pwn-var-replay
nc localhost 8011
```

Test the solver:

```
python3 solve.py REMOTE HOST=localhost PORT=8011
```

See `solve.md` for the full walkthrough and hint ladder.
