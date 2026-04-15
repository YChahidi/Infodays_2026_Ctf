#!/usr/bin/env python3
"""
var_override solver — Hidden Number Problem attack on biased-k ECDSA.

The signer's nonce generator uses `secrets.randbits(232)` instead of
the required 256 bits — every `k` is silently zero in its top 24
bits. That is a textbook HNP leak: each signature gives us an
affine relation `k_i = A_i + T_i * d (mod n)` where `k_i` is small.

Stack m such relations into a lattice and LLL finds a vector whose
coordinates are exactly the tiny `k_i`'s, encoding `d` along the
way. Construction is the standard Boneh-Venkatesan basis.

With a 24-bit leak, 15 signatures is plenty. LLL runs via
sympy.polys.matrices.DomainMatrix.lll (integer arithmetic, a few
seconds on the 17-dim basis).

Dependencies: pycryptodome (AES-GCM) and sympy (LLL).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from Crypto.Cipher import AES
from sympy import ZZ
from sympy.polys.matrices import DomainMatrix

# secp256k1 group order
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The signer leaks the top 24 bits of k (randbits(232))
LEAK_BITS = 24
K_BOUND = 1 << (256 - LEAK_BITS)

HERE = Path(__file__).resolve().parent
PUB = HERE.parent / "public"


# ---------------------------------------------------------------------------
# LLL reduction via sympy.polys.matrices.DomainMatrix.lll
# ---------------------------------------------------------------------------

def lll_reduce(basis):
    """LLL-reduce an integer basis and return the reduced rows as lists."""
    M = DomainMatrix.from_list(basis, ZZ)
    reduced = M.lll()
    return [[int(x) for x in row] for row in reduced.to_Matrix().tolist()]


# ---------------------------------------------------------------------------
# Signature loading + lattice construction
# ---------------------------------------------------------------------------

def load_signatures():
    out = []
    for line in (PUB / "signatures.txt").read_text().splitlines():
        if "|" not in line or not line.strip().startswith("VAR_"):
            continue
        msg, r, s = [p.strip() for p in line.split("|")]
        z = int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big")
        out.append((z, int(r), int(s)))
    return out


def build_lattice(sigs, n, K):
    m = len(sigs)
    T, A = [], []
    for z, r, s in sigs:
        sinv = pow(s, -1, n)
        T.append(r * sinv % n)
        A.append(z * sinv % n)

    dim = m + 2
    basis = [[0] * dim for _ in range(dim)]
    for i in range(m):
        basis[i][i] = n * n
    for i in range(m):
        basis[m][i] = T[i] * n
        basis[m + 1][i] = A[i] * n
    basis[m][m] = K
    basis[m + 1][m + 1] = K * n
    return basis


def recover_d(sigs, n, K):
    basis = build_lattice(sigs, n, K)
    reduced = lll_reduce(basis)
    m = len(sigs)

    def check(candidate):
        z, r, s = sigs[0]
        k = pow(s, -1, n) * (z + r * candidate) % n
        return 0 < k < 2 * K

    for row in reduced:
        last = row[m + 1]
        if abs(last) != K * n:
            continue
        sign = 1 if last > 0 else -1
        scaled = row[m] * sign
        if scaled % K != 0:
            continue
        d = (scaled // K) % n
        if check(d):
            return d
    return None


# ---------------------------------------------------------------------------
# Flag unwrap
# ---------------------------------------------------------------------------

def decrypt_flag(d: int) -> bytes:
    blob = (PUB / "flag.enc").read_bytes()
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    key = hashlib.sha256(d.to_bytes(32, "big")).digest()
    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(ct, tag)


def main() -> int:
    sigs = load_signatures()
    print(f"[+] loaded {len(sigs)} signatures")
    print("[*] running LLL on 17-dim HNP lattice…")
    d = recover_d(sigs, N_CURVE, K_BOUND)
    if d is None:
        print("[-] lattice attack failed — check LEAK_BITS / signature count")
        return 1
    print(f"[+] recovered priv key d = {hex(d)}")
    flag = decrypt_flag(d)
    print(f"[+] flag: {flag.decode()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
