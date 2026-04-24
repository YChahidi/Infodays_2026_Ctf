# leonel_messi

**Category:** Pwn
**Difficulty:** Medium–Hard
**Type:** TCP service — custom LM10 framing + 16-bit SHA-256 proof-of-work

## Player brief

> Leo Messi's private "Goal Journal" service — every note is a short
> entry you can stash and recall. Prove you deserve a seat at the
> training table and see how far your notes can reach.
>
> **Endpoint:** `nc <host> <port>`
>
> **Flag format:** `INFODAYS{SaamNoLimits_...}`
> **Flag lives at:** `/home/ctf/flag.txt` inside the container (mode 644).

## LM10 framing

Every request and response is a single frame:

```
+--------+----------+----------------------+
| "LM10" |  u16 BE  |    body (opcode +    |
|  4 B   |   len    |      payload)        |
+--------+----------+----------------------+
```

Opcodes:

| op   | name     | body after op byte               | success resp                     |
|------|----------|----------------------------------|----------------------------------|
| 0x0A | RECORD   | `u16 BE size` + `size` bytes     | `0x00 + u8 idx`                  |
| 0x1E | RECALL   | `u8 idx`                         | `0x00 + u16 BE len + content`    |
| 0x63 | CEREMONY | (empty — disconnect)             | —                                |

Error responses are `0xFF`. Indices span `0..7`.

## Proof-of-work gate

The *very first* frame the server sends is

```
"LM10" || u16(18) || 0xEE || nonce[16] || bits
```

with `bits = 0x10 = 16`. Reply with

```
"LM10" || u16(8) || 0xEF || suffix[7]
```

where `sha256(nonce || suffix)` has at least `bits` leading zero bits
(~30–50 ms in C, ~100 ms in Python).

## Hardening (build flags)

- Partial RELRO (`-Wl,-z,lazy`)
- Non-PIE (`-no-pie`)
- No stack canary (`-fno-stack-protector`)
- No FORTIFY (`-U_FORTIFY_SOURCE`)
- NX enabled (default)

## Files

| Path | Purpose |
|------|---------|
| `leonel_messi.c` | C source — LM10 server (build with the Dockerfile) |
| `Dockerfile` | Two-stage build (ubuntu:22.04 → ubuntu:22.04 runtime) |
| `entrypoint.sh` | Plants `$FLAG` into `/home/ctf/flag.txt`, then execs server |
| `solver/client.py` | LM10 reference client — PoW + record/recall |
| `solver/solve.py` | Full working exploit |
| `WRITEUP.md` | Staff-only solution walkthrough |

## Anti-AI hardening (intent)

1. **Custom LM10 framing** — no ASCII menu, no text prompts. An AI
   asked "write a solver" without the wire spec hallucinates menu
   parsing and fails on the first read.
2. **Per-connection PoW** — every session costs real CPU, so bulk
   "try every byte length until something crashes" automation runs
   into a multi-second-per-attempt floor.

In-source comments are terse — no vulnerability names, no exploit
recipe — so repository leaks do not spoil the challenge.

## Local testing

```bash
docker build -t leonel_messi .
docker run --rm -e FLAG="INFODAYS{test_flag}" -p 1337:1337 leonel_messi

# In another shell:
cd solver
# the solver needs a local copy of the built binary to resolve addresses
docker create --name _lm leonel_messi && docker cp _lm:/home/ctf/leonel_messi ./leonel_messi && docker rm _lm
python3 solve.py localhost 1337
```
