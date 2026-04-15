#!/usr/bin/env python3
"""
cipher_championship — build-time generator.

Produces three ciphertext files (one per round) plus a sibling flag.txt
listing the three flags, all tied together by a single random hex suffix.

    public/round1.txt   Repeating-key XOR ciphertext (easy)
    public/round2.txt   RSA ciphertext with e=3, no padding (medium)
    public/round3.txt   RSA ciphertext with small d, Wiener-vulnerable (hard)
    flag.txt            Three flags for the current build

Usage:
    python3 gen.py                  # random hex suffix
    python3 gen.py --hex a7f2c409   # deterministic build
"""

from __future__ import annotations

import argparse
import secrets
from math import gcd
from pathlib import Path

from Crypto.Util.number import getPrime, inverse

HERE = Path(__file__).resolve().parent
PUB = HERE / "public"
FLAG_PATH = HERE / "flag.txt"


def gen_round1(flag1: bytes) -> str:
    """Repeating-key XOR. The plaintext starts with a known crib so the
    player can recover the key by XOR-ing the first few ciphertext bytes
    with the crib."""
    key = secrets.token_bytes(5)
    plaintext = b"Flag: " + flag1 + b"\n"
    ct = bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))
    return (
        "=== Round 1 — Half-time Scoreboard ===\n"
        "\n"
        "You intercepted a scoreboard update from the Infodays press\n"
        "office. It was XOR'd with a short, repeating key. The message\n"
        "begins with a predictable banner — use that.\n"
        "\n"
        f"ciphertext_hex = {ct.hex()}\n"
        "\n"
        "Hint: repeating-key XOR, key length somewhere between 3 and 8\n"
        "bytes. The plaintext opens with the literal string 'Flag: '\n"
        "followed by the usual INFODAYS flag format.\n"
    )


def gen_round2(flag2: bytes) -> str:
    """RSA with e=3 and no padding. The plaintext is short enough that
    m^3 < n, so cube-root recovers the message without modular
    reduction."""
    e = 3
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break
    n = p * q
    m = int.from_bytes(flag2, "big")
    assert pow(m, e) < n, "message too large — m^3 would wrap n"
    c = pow(m, e, n)
    return (
        "=== Round 2 — The Away Goal ===\n"
        "\n"
        "The Infodays ticketing system encrypted a short admin note with\n"
        "an RSA public key. Somebody forgot that textbook RSA with a\n"
        "small public exponent is a bad idea for short messages.\n"
        "\n"
        f"n = {n}\n"
        f"e = {e}\n"
        f"c = {c}\n"
        "\n"
        "Hint: the message is short, e is tiny. Work out what m^e looks\n"
        "like when m^e is less than n. The plaintext is a UTF-8 string\n"
        "starting with the usual flag banner.\n"
    )


def gen_round3(flag3: bytes) -> str:
    """RSA with small d — Wiener's attack.

    Pick d with d < (1/3) * n^(1/4), then e = d^-1 mod phi. Because d is
    tiny, e ≈ phi ≈ n, so the continued-fraction expansion of e/n has
    a convergent whose denominator is exactly d.
    """
    while True:
        p = getPrime(512)
        q = getPrime(512)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # Wiener bound: d < n^(1/4) / 3
        bound = int(pow(n, 0.25) / 3)
        # Pick d well below bound (200 bits << 256-bit bound)
        while True:
            d = secrets.randbits(200) | 1
            if d > 1 and d < bound and gcd(d, phi) == 1:
                break
        try:
            e = inverse(d, phi)
        except ValueError:
            continue
        # Sanity: verify e is large (this is what makes Wiener work)
        if e.bit_length() < n.bit_length() - 8:
            continue
        m = int.from_bytes(flag3, "big")
        if m >= n:
            continue
        c = pow(m, e, n)
        break
    return (
        "=== Round 3 — Lifting the Trophy ===\n"
        "\n"
        "The Infodays trophy vault is gated by an RSA signature scheme.\n"
        "An audit leaked the public key. The private exponent was picked\n"
        "suspiciously small 'for performance'.\n"
        "\n"
        f"n = {n}\n"
        f"e = {e}\n"
        f"c = {c}\n"
        "\n"
        "Hint: notice how big e is relative to n. When the private\n"
        "exponent d is small enough (roughly d < n^0.25 / 3), there is\n"
        "a classical attack that recovers d from the continued-fraction\n"
        "expansion of e/n. Then decryption is ordinary: m = c^d mod n.\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None, help="override the random hex suffix")
    args = ap.parse_args()

    rand_hex = args.hex or secrets.token_hex(4)

    flag1 = f"INFODAYS{{SaamNoLimits_xor_broken_at_halftime_{rand_hex}}}".encode()
    flag2 = f"INFODAYS{{SaamNoLimits_cube_root_away_goal_{rand_hex}}}".encode()
    flag3 = f"INFODAYS{{SaamNoLimits_wiener_raised_the_trophy_{rand_hex}}}".encode()

    PUB.mkdir(parents=True, exist_ok=True)
    (PUB / "round1.txt").write_text(gen_round1(flag1))
    (PUB / "round2.txt").write_text(gen_round2(flag2))
    (PUB / "round3.txt").write_text(gen_round3(flag3))

    FLAG_PATH.write_text("\n".join(f.decode() for f in (flag1, flag2, flag3)) + "\n")

    print(f"[gen] hex={rand_hex}")
    print(f"[gen] wrote {PUB}/round{{1,2,3}}.txt")
    print(f"[gen] flags -> {FLAG_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
