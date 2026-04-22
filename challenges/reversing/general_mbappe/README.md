# general_mbappe

**Manifest:** [`challenges/manifests/reversing-general-mbappe.yaml`](../../manifests/reversing-general-mbappe.yaml)
**Static content:** [`challenges/static-content/reversing-general-mbappe/`](../../static-content/reversing-general-mbappe/)
**Category:** Reversing
**Difficulty:** Hard
**Type:** `static` — file download only, no container

## Player brief

> Le général Mbappé has been tampering with low-level things again.
> He wrote his own kitchen ISA, then built a tiny `cook` that reads
> a `recipe` written in it — an obvious AES-256 derivation chain
> crammed into a custom virtual machine.  Decrypt the recipe, find
> the kitchen pass le général is guarding, and claim the flag.
>
> **Attached:** `cook` (ELF x86-64, stripped), `recipe.asm` (text),
> and `general_mbappe.webp` (poster art — le général on the bench).
>
> **Flag format:** `infodays{SaamNoLimits_<kitchen_pass>}`

> The challenge description above is **deliberately misleading**.
> AES-256 has nothing to do with the actual solve; `AES256` is just
> the print-char mnemonic in the kitchen ISA.

## Anti-AI design

This challenge is built to resist solving by pasting files into an
LLM.  Two of the seven principles from the CTF brief apply directly:

* **Multi-modal reasoning (#2).**  The 32-byte permutation table
  PERM that the recipe uses to shuffle the input is **not** present
  in `recipe.asm` or in the `cook` binary.  It is smuggled as an
  appended trailer on `general_mbappe.webp`.  Any solver that reads
  only the text/code files but never opens the image will be unable
  to reconstruct PERM, and the recipe's LADDER immediates alone are
  insufficient.
* **Obfuscated intent (#5).**  The recipe is peppered with noise
  opcodes (`FLAMBE`) and a 32-byte decoy block at `mem[0x40..0x5F]`
  whose bytes match the first half of the AES-256 forward S-box.
  An LLM that pattern-matches on "AES S-box" will spend its tokens
  on a rabbit hole — the bytes are loaded but never read back.

## How the cook runs

```
./cook recipe.asm spice.bin
```

`spice.bin` is a 32-byte file that gets loaded into `mem[0xA0..0xBF]`
before the recipe starts.  The recipe reads it indirectly via
`MOVR CARBO, LADLE` — the textual recipe never mentions the
permutation values.  The only copy of PERM shipped to players is
the trailer on the webp.

## Intended solve path

1.  Inspect the webp with `xxd` / a hex editor.  Find the `MBSP`
    magic near the tail, the one-byte version, one-byte length,
    and a 32-byte payload terminated by `MBEP`.  Save the payload
    as `spice.bin`.
2.  Parse `recipe.asm` for the 32 `LADDER TMP, 0x??, FAIL` lines —
    these are the expected shuffled bytes, call them `key[i]`.
3.  With PERM and key in hand: `pass[PERM[i]] = key[i]`, so
    `pass[j] = key[PERM^-1[j]]`.  Invert and decode.

See [WRITEUP.md](WRITEUP.md) for the full author solution, and
[solver/solve.py](solver/solve.py) for a reference implementation.

## Files

| Path                          | Purpose                                          |
|-------------------------------|--------------------------------------------------|
| `src/cook.c`                  | VM interpreter source                            |
| `dist/cook`                   | Compiled, stripped binary (player-facing)       |
| `dist/recipe.asm`             | Generated recipe (player-facing)                |
| `dist/spice.bin`              | PERM bytes — author-only, **never shipped**     |
| `dist/general_mbappe.webp`    | Stego'd image (player-facing)                   |
| `gen.py`                      | Rebuilds recipe + spice + flag                  |
| `stego.py`                    | Embeds/extracts spice trailer on the webp       |
| `solver/solve.py`             | Reference solver — needs recipe + image         |
| `flag.txt`                    | Current build's flag (author-side)              |
| `WRITEUP.md`                  | Author's solution                                |
| `Makefile`                    | Build, embed, stage, self-test                  |

## Build and self-test

```bash
make            # builds cook, recipe.asm, spice.bin, stego'd webp, stages to static-content
make test       # runs the intended solve end-to-end
```

## Deployment (INFODAYS CTF infra)

This challenge follows the static-download model:

1.  **Manifest** lives at
    [`challenges/manifests/reversing-general-mbappe.yaml`](../../manifests/reversing-general-mbappe.yaml)
    with `type: static`, no `image:`, no `port:`.
2.  **Player files** live at
    [`challenges/static-content/reversing-general-mbappe/`](../../static-content/reversing-general-mbappe/):
    `cook`, `recipe.asm`, and `general_mbappe.webp`.
    **No `flag.txt`, no `spice.bin`** — the deploy plugin injects a
    unique per-team `flag.txt`; the spice only ever exists as the
    webp trailer.
3.  Running `make` rebuilds both artifacts and stages them
    automatically.
4.  Deploy with
    `bash scripts/deploy-challenge.sh challenges/manifests/reversing-general-mbappe.yaml`.
