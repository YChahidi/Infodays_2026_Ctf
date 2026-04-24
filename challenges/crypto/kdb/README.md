# KDB (v2 / INSANE)

**Category:** Crypto (custom KEM / noisy MaxSAT / AES-GCM)
**Difficulty:** Insane
**Service:** TCP on port `9001`
**Handout:** `handout/protocol.py` + `handout/service.py`

### What changed from v1

1. **No anchor** — the transcript no longer publishes `kickoff_basis`.
   Global basis flip is ambiguous until the attacker reconciles with a
   separate fingerprint check.
2. **Noisy sifting** — every frame's sifting bits carry ~10% random
   corruption.  A plain Z3 solve returns UNSAT; attackers need a
   MaxSAT / weighted optimisation (e.g. `z3.Optimize.add_soft`) and
   must tolerate that a chunk of the transcript is wrong.
3. **AES-GCM transport** — commands ride under AEAD with a
   protocol-derived nonce.  Single-bit errors in the recovered key
   fail the GCM auth tag, so there's no "try it and see" fallback.

## Player brief

> Kevin De Bruyne runs a private "Pass Signal Protocol" relay out of
> Bruges to coordinate late-game substitution calls. Courier traffic
> is encrypted with a session key agreed via a classical
> frame-based key exchange.
>
> Only someone holding that key can send an `OPEN THE GATE` command
> and retrieve the locker-room coordinates (+ the prize).
>
> You have the full protocol source and the wire transcript — enough
> to reconstruct the session key without ever touching KDB's private
> measurement basis.

## Flag format

`INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## The protocol (also in `handout/protocol.py`)

- Basis pool of 64 slots, each with a secret bit `basis[i] ∈ {0, 1}`
  ("X" or "Z").
- 256 frames; each frame is `(a, b, m_a, m_b)` with two distinct pool
  indices and two per-frame measurement bits.
- Published per frame: `"{s_X}{s_Z},{m_a}{m_b}"` where
  `s_X = (m_a if basis[a]==0 else 0) ^ (m_b if basis[b]==0 else 0)` and
  `s_Z` is the mirror for `basis==1`.
- Ambiguous frames (= any frame with `m_a != 1` or `m_b != 1`) are
  excluded from the key.  Non-ambiguous frames end in `,11`.
- Public transcript also includes `kickoff_basis` — literally
  `basis[0]` — so the attacker can resolve the global flip ambiguity.

## Deployment

`type: tcp`, port `9001` inside the pod, NodePort `30035` externally.

```
docker compose up --build
nc 127.0.0.1 9001
```

Every connection spawns a fresh session; no shared state between
clients.

## Files

```
kdb/
├── README.md
├── WRITEUP.md
├── flag.txt                 # INFODAYS{...}
├── docker-compose.yml
├── src/
│   ├── protocol.py          # frame generator + key derivation
│   ├── server.py            # TCP service
│   ├── requirements.txt
│   └── Dockerfile
├── handout/
│   ├── protocol.py          # == src/protocol.py, shipped to players
│   └── service.py           # == src/server.py, shipped to players
└── solver/
    └── solve.py             # full Z3-based solve
```

## Author notes

- The Z3 system is over-determined in practice; non-ambiguous frames
  alone usually give a connected equality/inequality graph over ~60+
  of the 64 basis slots, and ambiguous frames with exactly one
  `m=1` side pin individual basis bits directly.
- Shared key length varies per session (≈ 60-70 bits because only
  ~25% of frames are non-ambiguous).  SHA-256 collapses that into a
  uniform 256-bit AES key.
- The `kickoff_basis` anchor is NOT decorative — without it the Z3
  model has a global-flip twin that yields the bit-complement of the
  real key.  If a future variant removes the anchor, switch the
  solver to publish a short `sha256(key)` fingerprint and try both
  candidates.
