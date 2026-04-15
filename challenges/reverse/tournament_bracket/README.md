# tournament_bracket

**Category:** Reverse Engineering
**Difficulty:** Insane (3 flags — Easy → Medium → Hard)
**Type:** Static binary (file attachment, no container)

## Player brief

> The Infodays 2026 tournament committee built a single binary to gate
> access to three stages of the event: the group stage, the knockout
> round, and the final. Each stage hides a flag. Pass all three rounds
> and you raise the trophy.
>
> Three flags. One binary. Three difficulty levels stacked inside.
>
> **Attached:** `tournament` (Linux x86-64 ELF, stripped)
>
> **Flag format (per stage):** `INFODAYS{SaamNoLimits_<phrase>}`

## The three stages

| # | Stage       | Difficulty | Technique |
|---|-------------|------------|-----------|
| 1 | Group Stage | Easy       | Static XOR check — recover the passphrase with basic RE |
| 2 | Knockout    | Medium     | Custom stack-VM bytecode interpreter — reverse the VM, then the program |
| 3 | Final       | Hard       | 16-variable linear system — solve with Z3 or linear algebra |

Each stage's flag is **XOR-encrypted in `.rodata` with the correct
passphrase as the key**, so `strings` leaks nothing. Players must
actually solve each stage to decrypt its flag.

## Deployment

Pure static attachment. No container, no port, no runtime.

1. Build once: `make` (produces `dist/tournament`)
2. Upload `dist/tournament` to CTFd as a file attachment
3. Set the three flags (one per challenge, or one challenge with 3
   flag checkpoints if you prefer) using the values in `flag.txt`

### Regenerating the binary

Flags are baked in at build time via `gen.py`, which randomises all
XOR keys, VM bytecode, and linear coefficients on every call. The three
**passphrases** stay constant (`tiki_taka_baby`, `route_one_go`,
`penalty_shootout`) so the intended-solution writeup stays valid — what
changes is the encryption layer around the flag bodies and the hex
suffix baked into each flag string.

```bash
# Regenerate with a fresh random hex
python3 gen.py
make clean && make

# Regenerate with a specific hex (for reproducible builds)
python3 gen.py --hex a7f2c409
make clean && make
```

## Files

| Path | Purpose |
|------|---------|
| `src/tournament.c` | Source (generated — do not hand-edit) |
| `dist/tournament` | Compiled binary — this is the player-facing artifact |
| `solver/solve_r1.py` | Round 1 solver (XOR) |
| `solver/solve_r2.py` | Round 2 solver (VM bytecode disassembly) |
| `solver/solve_r3.py` | Round 3 solver (Z3) |
| `gen.py` | Build-time generator — rewrites `src/tournament.c` with fresh random constants |
| `Makefile` | Build + self-test |
| `flag.txt` | The three flags for the current build |
| `WRITEUP.md` | Full author solution |

## Build and self-test

```bash
make            # compiles dist/tournament
make test       # pipes the three passphrases and prints all 3 flags
```

## Current flags (build `a7f2c409`)

```
INFODAYS{SaamNoLimits_group_stage_survived_a7f2c409}
INFODAYS{SaamNoLimits_knockout_blow_landed_a7f2c409}
INFODAYS{SaamNoLimits_raised_the_trophy_a7f2c409}
```

These rotate if you rerun `gen.py` without `--hex`. Regenerate before
publishing if you want a different hex suffix.
