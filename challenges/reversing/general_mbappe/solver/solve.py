#!/usr/bin/env python3
"""
GENERAL MBAPPE solver — multi-modal.

The recipe alone is NOT solvable.  The 32-byte permutation PERM
is hidden in the trailer of the webp image shipped with the zip.
This script does both halves:

    1. extract PERM from the image trailer (MBSP...MBEP frame)
    2. read the 32 LADDER immediates (key) from recipe.asm
    3. invert PERM: pass[PERM[i]] = key[i]  =>  pass[j] = key[PERM^-1[j]]

    Usage:  python3 solve.py <recipe.asm> <image.webp>
"""
import os
import re
import sys

MAGIC_START = b"MBSP"
MAGIC_END   = b"MBEP"


def extract_perm(image_path: str) -> bytes:
    with open(image_path, "rb") as f:
        data = f.read()
    idx = data.rfind(MAGIC_START)
    if idx == -1 or not data.endswith(MAGIC_END):
        raise SystemExit(f"no MBSP trailer in {image_path} — wrong image?")
    length  = data[idx + 5]
    start   = idx + 6
    payload = data[start:start + length]
    if len(payload) != length:
        raise SystemExit("truncated payload")
    return payload


LADDER_RE = re.compile(
    r"^\s*LADDER\s+TMP\s*,\s*0x([0-9a-fA-F]{2})\s*,\s*FAIL",
    re.IGNORECASE,
)


def extract_key(asm_text: str) -> bytes:
    key = []
    for line in asm_text.splitlines():
        line = line.split(";", 1)[0]
        m = LADDER_RE.match(line)
        if m:
            key.append(int(m.group(1), 16))
    if len(key) != 32:
        raise SystemExit(f"expected 32 LADDER checks, found {len(key)}")
    return bytes(key)


def invert_perm(perm: bytes) -> list:
    """Return P^-1 such that P^-1[P[i]] == i."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <recipe.asm> <image.webp>")
        sys.exit(2)
    recipe_path = sys.argv[1]
    image_path  = sys.argv[2]

    perm = extract_perm(image_path)
    if sorted(perm) != list(range(32)):
        raise SystemExit("extracted trailer is not a permutation of 0..31")

    with open(recipe_path) as f:
        key = extract_key(f.read())

    inv = invert_perm(perm)
    # pass[PERM[i]] = key[i]  =>  pass[j] = key[PERM^-1[j]]
    plain = bytes(key[inv[j]] for j in range(32))
    flag = f"infodays{{SaamNoLimits_{plain.decode()}}}"
    print(f"[+] spice        = {perm.hex()}")
    print(f"[+] kitchen pass = {plain.decode()}")
    print(f"[+] flag         = {flag}")


if __name__ == "__main__":
    main()
