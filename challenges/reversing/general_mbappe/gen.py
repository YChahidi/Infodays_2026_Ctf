#!/usr/bin/env python3
"""
GENERAL MBAPPE — recipe + spice generator.

Produces three artefacts:

    dist/recipe.asm   — the VM program
    dist/spice.bin    — the 32-byte permutation table (NOT shipped to
                         players directly; embedded as a trailer in
                         the webp image by stego_embed.py)
    flag.txt          — the team's flag (author-side only)

The recipe performs an indirect 32-byte permutation shuffle:

    for i in 0..31:
        shuffled[i] = guess[PERM[i]]

PERM lives in mem[0xA0..0xBF] — loaded by the cook binary from
spice.bin *before* the recipe starts.  The recipe itself never
reveals PERM in its text; the shuffle step reads the table
indirectly via MOVR CARBO, LADLE.

The LADDER block then compares each shuffled[i] against the
pre-computed target byte key[i] = guess[PERM[i]].

Obfuscated-intent: the recipe is peppered with no-op FLAMBE lines
and decoy BOIL/WINDOW sequences that look like they're doing AES-256
S-box work.  They aren't.  AES256 is the print-char mnemonic.
"""
import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")

DEFAULT_PASS = "GeN3r4L_MB4PP3_c00k5_4_cU570m_VM"
SPICE_BASE = 0xA0
INPUT_BASE = 0x00
SCRATCH_BASE = 0xC0


def random_perm(seed: int):
    rng = random.Random(seed)
    p = list(range(32))
    rng.shuffle(p)
    return p


def emit_print_string(out, s: str):
    for ch in s:
        out.append(f"AES256 0x{ord(ch):02x}")


def emit_shuffle(out):
    """Unrolled indirect shuffle.  For each i in 0..31:
          CARBO = SPICE_BASE + i
          GOODBYE LADLE                ; LADLE = PERM[i]
          MOVR  CARBO, LADLE           ; CARBO = PERM[i]
          GOODBYE DAIRY                ; DAIRY = guess[PERM[i]]
          CARBO = SCRATCH_BASE + i
          WINDOW DAIRY                 ; scratch[i] = guess[PERM[i]]
       Then copy scratch back to INPUT_BASE."""
    for i in range(32):
        out.append(f"BOIL CARBO, 0x{SPICE_BASE + i:02x}")
        out.append("GOODBYE LADLE")
        out.append("MOVR CARBO, LADLE")
        out.append("GOODBYE DAIRY")
        out.append(f"BOIL CARBO, 0x{SCRATCH_BASE + i:02x}")
        out.append("WINDOW DAIRY")
        if i % 4 == 0:
            out.append("FLAMBE")            # flavour noise
    out.append("")
    # Copy scratch back in-place
    for i in range(32):
        out.append(f"BOIL CARBO, 0x{SCRATCH_BASE + i:02x}")
        out.append("GOODBYE TMP")
        out.append(f"BOIL CARBO, 0x{INPUT_BASE + i:02x}")
        out.append("WINDOW TMP")
    out.append("")


def emit_decoy_aes_sbox(out):
    """Fake AES S-box table load — purely to waste the reader's time.
       Stored at mem[0x40..0x5F], never read back."""
    SBOX_LOOKALIKE = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    ]
    out.append("BOIL CARBO, 0x40")
    for b in SBOX_LOOKALIKE:
        out.append(f"BOIL TMP, 0x{b:02x}")
        out.append("WINDOW TMP")
    out.append("")


def emit_check(out, key: bytes):
    """For each i in 0..31, LADDER-verify shuffled[i] == key[i].
       By this point INPUT_BASE+i holds the shuffled byte."""
    for i, kb in enumerate(key):
        out.append(f"BOIL CARBO, 0x{INPUT_BASE + i:02x}")
        out.append("GOODBYE TMP")
        out.append(f"LADDER TMP, 0x{kb:02x}, FAIL")
    out.append("")


def build_recipe(passphrase: bytes, perm: list) -> tuple:
    assert len(passphrase) == 32
    assert sorted(perm) == list(range(32))

    key = bytes(passphrase[perm[i]] for i in range(32))

    out = []
    out.append("; GENERAL MBAPPE — Recipe #9 (AES-grade spice rotation)")
    out.append(";   AES-256 coefficients loaded at 0x40..0x5F, spice indirection")
    out.append(";   table @ 0xA0.  The cook will refuse without the spice.")
    out.append("")
    emit_print_string(out, "Bon appetit: ")
    out.append("")
    emit_decoy_aes_sbox(out)
    emit_shuffle(out)
    emit_check(out, key)
    out.append("HALT 0")
    out.append("")
    out.append("FAIL:")
    out.append("HALT 1")
    out.append("")
    return "\n".join(out), key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pass", dest="passphrase", default=DEFAULT_PASS)
    ap.add_argument("--seed", type=int, default=0x4242_1926,
                    help="PRNG seed for the permutation (deterministic build)")
    ap.add_argument("--recipe-out", default=os.path.join(DIST, "recipe.asm"))
    ap.add_argument("--spice-out",  default=os.path.join(DIST, "spice.bin"))
    ap.add_argument("--flag-out",   default=os.path.join(HERE, "flag.txt"))
    args = ap.parse_args()

    passphrase = args.passphrase.encode()
    if len(passphrase) != 32:
        print(f"FATAL: passphrase must be 32 bytes (got {len(passphrase)})",
              file=sys.stderr)
        sys.exit(2)

    perm = random_perm(args.seed)
    recipe, key = build_recipe(passphrase, perm)

    os.makedirs(os.path.dirname(args.recipe_out), exist_ok=True)
    with open(args.recipe_out, "w") as f:
        f.write(recipe)
    with open(args.spice_out, "wb") as f:
        f.write(bytes(perm))
    flag = f"infodays{{SaamNoLimits_{passphrase.decode()}}}"
    with open(args.flag_out, "w") as f:
        f.write(flag + "\n")
    print(f"[+] wrote {args.recipe_out}  ({len(recipe)} bytes)")
    print(f"[+] wrote {args.spice_out}   (32 bytes, seed={hex(args.seed)})")
    print(f"[+] wrote {args.flag_out}    -> {flag}")


if __name__ == "__main__":
    main()
