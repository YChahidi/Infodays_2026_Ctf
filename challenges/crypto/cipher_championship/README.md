# cipher_championship

**Category:** Cryptography
**Difficulty:** Insane (3 flags — Easy → Medium → Hard)
**Type:** Static file attachment (no container, no port)

## Player brief

> The Infodays 2026 cryptography championship runs in three rounds.
> Each round, the organisers post an intercepted ciphertext to the
> scoreboard. Crack the round's ciphertext and you earn the flag.
>
> Three rounds. Three ciphers. One championship.
>
> **Attached:** `round1.txt`, `round2.txt`, `round3.txt`
>
> **Flag format (per round):** `INFODAYS{SaamNoLimits_<phrase>_<hex>}`

## The three rounds

| # | Round             | Difficulty | Technique |
|---|-------------------|------------|-----------|
| 1 | Half-time         | Easy       | Repeating-key XOR with a known-plaintext crib |
| 2 | The Away Goal     | Medium     | Textbook RSA with e=3, no padding — cube-root attack |
| 3 | Lifting the Trophy| Hard       | RSA with small private exponent — Wiener's attack |

Each round is self-contained: players get a short story snippet and
the ciphertext parameters. No server, no API — pure pen-and-paper
(and Python) crypto.

## Deployment

Pure static attachment. No container, no port, no runtime.

1. Build once: `python3 gen.py` (writes `public/round{1,2,3}.txt` and `flag.txt`)
2. Upload each `public/roundN.txt` as the file attachment for round N
3. Read `flag.txt` and paste the three flags into CTFd

### Regenerating the bundle

Flags are baked in at build time via `gen.py`. Every invocation
re-randomises the XOR key, RSA primes, and Wiener private exponent,
and rotates the hex suffix inside each flag string.

```bash
# Fresh random hex suffix every build
python3 gen.py

# Deterministic build (useful for reproducible testing)
python3 gen.py --hex a7f2c409
```

## Files

| Path | Purpose |
|------|---------|
| `gen.py` | Build-time generator — writes public/ bundle + flag.txt |
| `public/round1.txt` | XOR ciphertext — player-facing |
| `public/round2.txt` | RSA e=3 ciphertext — player-facing |
| `public/round3.txt` | RSA Wiener ciphertext — player-facing |
| `flag.txt` | The three flags for the current build |
| `solver/solve_r1.py` | Round 1 solver (crib-drag XOR) |
| `solver/solve_r2.py` | Round 2 solver (integer cube root) |
| `solver/solve_r3.py` | Round 3 solver (Wiener via continued fractions) |
| `WRITEUP.md` | Full author solution |

## Requirements

- Python 3.10+
- `pycryptodome` (for `gen.py` only — solvers use stdlib)

```bash
pip install pycryptodome
```

## Quick self-test

```bash
python3 gen.py --hex a7f2c409
python3 solver/solve_r1.py
python3 solver/solve_r2.py
python3 solver/solve_r3.py
cat flag.txt
```

All three solvers should print the exact flag strings from `flag.txt`.

## Current flags (build `a7f2c409`)

```
INFODAYS{SaamNoLimits_xor_broken_at_halftime_a7f2c409}
INFODAYS{SaamNoLimits_cube_root_away_goal_a7f2c409}
INFODAYS{SaamNoLimits_wiener_raised_the_trophy_a7f2c409}
```

These rotate if you rerun `gen.py` without `--hex`.
