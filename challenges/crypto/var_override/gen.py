#!/usr/bin/env python3
"""
var_override — build-time dataset generator.

Runs the player-facing signer (public/signer.py) to build the
distribution bundle:

    public/public_key.txt     Qx, Qy of the signer's public key
    public/signatures.txt     15 signed VAR decisions (decision | r | s)
    public/flag.enc           AES-GCM flag ciphertext; key = SHA256(priv)
    flag.txt                  Plaintext flag for the current build

Usage:
    python3 gen.py                  # random hex suffix
    python3 gen.py --hex a7f2c409   # deterministic build suffix
"""

from __future__ import annotations

import argparse
import hashlib
import secrets
import sys
from pathlib import Path

from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parent
PUB = HERE / "public"
sys.path.insert(0, str(PUB))

from signer import G, n, scalar_mul, sign_decision, verify  # noqa: E402

NUM_SIGS = 15


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", default=None, help="override the random hex suffix")
    args = ap.parse_args()

    rand_hex = args.hex or secrets.token_hex(4)

    # Fresh random private key per build.
    while True:
        priv = int.from_bytes(secrets.token_bytes(32), "big") % n
        if 1 < priv < n - 1:
            break
    pub = scalar_mul(priv, G)

    decisions = [
        f"VAR_DECISION_{i:03d}_match_{rand_hex}_final"
        for i in range(NUM_SIGS)
    ]

    sigs = []
    for msg in decisions:
        r, s = sign_decision(priv, msg.encode())
        assert verify(pub, msg.encode(), (r, s))
        sigs.append((msg, r, s))

    PUB.mkdir(parents=True, exist_ok=True)

    (PUB / "public_key.txt").write_text(
        "=== Infodays 2026 — VAR signer public key (secp256k1) ===\n"
        f"\nQx = {pub[0]}\nQy = {pub[1]}\n"
    )

    lines = [
        "=== 15 intercepted VAR decision signatures ===",
        "",
        "Format: decision | r | s",
        "Signature scheme: secp256k1 ECDSA over SHA-256(decision)",
        "",
    ]
    for msg, r, s in sigs:
        lines.append(f"{msg} | {r} | {s}")
    (PUB / "signatures.txt").write_text("\n".join(lines) + "\n")

    flag = f"INFODAYS{{SaamNoLimits_hnp_lattice_var_override_{rand_hex}}}".encode()
    key = hashlib.sha256(priv.to_bytes(32, "big")).digest()
    nonce = secrets.token_bytes(12)
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(flag)
    (PUB / "flag.enc").write_bytes(nonce + tag + ct)

    (HERE / "flag.txt").write_text(flag.decode() + "\n")

    print(f"[gen] hex={rand_hex}")
    print(f"[gen] priv (debug) = {hex(priv)}")
    print(f"[gen] Q = ({hex(pub[0])}, {hex(pub[1])})")
    print(f"[gen] wrote {PUB}/public_key.txt, signatures.txt, flag.enc")
    print(f"[gen] flag -> {HERE}/flag.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
