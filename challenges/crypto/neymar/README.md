# neymar

**Category:** Cryptography
**Difficulty:** Insane
**Type:** TCP service — custom FFP1 framing + SHA-256 proof-of-work gate

## Player brief

> PSG's scout network runs on a proprietary "Football Frame Protocol"
> (FFP1) dispatch channel. Every connection is gated by a cheap
> proof-of-work; once past, scout and dispatcher negotiate a *match
> cipher* and the dispatcher will only act on plays encrypted under
> it. Relay the right play — you reach Neymar.
>
> **Endpoint:** `nc <host> <port>`
>
> **Flag format:** `INFODAYS{SaamNoLimits_...}`

You are given only the endpoint. No source, no handout. Figure out the
frame format and the handshake from what goes over the wire.

## FFP1 frame format (player-discoverable)

Every message is a single frame:

```
+--------+----------+------------------------+
| "FFP1" | len (BE) | payload (JSON, UTF-8)  |
|  4 B   |   2 B    |       len bytes         |
+--------+----------+------------------------+
```

Every JSON payload has an `"op"` field that describes its purpose
(`pow`, `greet`, `handshake`, `ready`, `play`, `flag`, `err`).

### Proof-of-work

On connect the server sends an `op: "pow"` frame containing a 16-byte
`challenge` (hex) and a `bits` count (18). Find a `nonce` (arbitrary
byte string, hex-encoded, ≤ 32 bytes) such that

```
sha256(b"ffp1-pow:" + challenge + nonce)
```

has at least `bits` leading zero bits. Reply with
`{"op": "pow", "nonce": "<hex>"}`. ~0.5 s of CPU on a laptop.

## Deployment

TCP service on container port `1337`. The flag is injected at runtime
via the `FLAG` env var (rendered into `/app/flag.txt` by
`entrypoint.sh`), matching the rest of the repo.

| Env var         | Default | Purpose                                    |
|-----------------|---------|--------------------------------------------|
| `FLAG`          | —       | Flag value, required                       |
| `FFP_PAIRS`     | `1024`  | Handshake input size                       |
| `FFP_SECURITY`  | `32`    | Min match-cipher length (bits)             |
| `FFP_POW_BITS`  | `18`    | PoW difficulty (leading zero bits)         |

## Files

| Path | Purpose |
|------|---------|
| `server/challenge.py` | FFP1 main loop (PoW → handshake → AES command) |
| `server/ffp.py` | Framing + PoW primitives |
| `server/alice.py` | Scout side of the handshake |
| `server/bob.py` | Dispatcher side of the handshake |
| `server/helpers.py` | Static derivation tables |
| `server/secret.py` | Flavor prefix for the flag message |
| `Dockerfile` / `entrypoint.sh` | socat-forked alpine container |
| `solver/solve.py` | Intended solver (PoW miner + z3 + AES) |
| `flag.txt` | Local flag for out-of-cluster testing |
| `WRITEUP.md` | Staff-only solution walkthrough |

## Anti-AI hardening (intent)

This lab is explicitly hardened against copy-paste-into-ChatGPT
solutions. Three layers:

1. **Lexical detachment from public writeups** — the wire protocol
   uses football-native field names (`registered_plays`, `tactics`,
   `chalkboard_codes`, `vetoed_tactics`, command `"PASS TO NEYMAR"`).
   Web-search on any of those returns nothing relevant.
2. **Custom FFP1 framing** — raw "send JSON on stdin" clients
   (including naïve LLM-generated ones) get rejected by the header
   parser. Players must implement the magic+length wrapper before
   they can send a single message.
3. **Per-connection PoW gate** — 18-bit SHA-256 PoW per connect. Cheap
   for a human solving once, expensive for agent-style brute forcing
   (thousands of reconnects → hours of CPU).

The underlying cryptanalytic bug is still the same principled
sifting-leak → z3 recovery used in the intended solution. The three
layers above only prevent trivial "ask the AI to write a solver from
one hint" attacks; a student who actually reasons about the protocol
still solves it in a few hours.

## Local testing

```bash
docker build -t neymar .
docker run --rm -e FLAG="INFODAYS{test}" -p 1337:1337 neymar

# In another shell:
pip install pycryptodome z3-solver
python3 solver/solve.py localhost 1337
```

The solver spends ~0.5 s mining the PoW, ~0.3 s in z3, and returns
the flag.
