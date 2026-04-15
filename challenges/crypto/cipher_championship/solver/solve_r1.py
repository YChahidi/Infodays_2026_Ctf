#!/usr/bin/env python3
"""
Round 1 solver — repeating-key XOR with a known-plaintext crib.

The ciphertext encrypts `b"Flag: " + flag + b"\n"` under a short
repeating key (length 3..8). The first six plaintext bytes are the
literal banner "Flag: ", so XOR'ing the first six ciphertext bytes
against that crib leaks the first six key bytes. Because the key
length is unknown, we try every candidate length and keep the one
whose recovered plaintext decodes as clean ASCII starting with the
expected banner.
"""

import re
import sys
from pathlib import Path

CRIB = b"Flag: "


def recover(ct: bytes) -> tuple[bytes, bytes]:
    for klen in range(3, 9):
        if len(ct) < klen:
            continue
        key = bytes(ct[i] ^ CRIB[i] for i in range(min(klen, len(CRIB))))
        if len(key) < klen:
            continue
        pt = bytes(c ^ key[i % klen] for i, c in enumerate(ct))
        if pt.startswith(CRIB) and all(32 <= b < 127 or b in (9, 10) for b in pt):
            return key, pt
    raise SystemExit("[-] no candidate key length worked")


def main() -> int:
    here = Path(__file__).resolve().parent
    txt = (here.parent / "public" / "round1.txt").read_text()
    m = re.search(r"ciphertext_hex\s*=\s*([0-9a-fA-F]+)", txt)
    if not m:
        print("[-] ciphertext_hex not found in round1.txt", file=sys.stderr)
        return 1
    ct = bytes.fromhex(m.group(1))
    key, pt = recover(ct)
    print(f"[+] recovered key  : {key!r}  (len={len(key)})")
    print(f"[+] plaintext      : {pt.decode().rstrip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
