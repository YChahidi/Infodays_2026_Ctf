#!/usr/bin/env python3
"""
Infodays 2026 — VAR Override Signing Service (reference source).

This is the full source of the referee signing service that stamps
every VAR decision before it is published to the scoreboard. The
board team shipped this exact file to the audit panel, so you have
it in your hands.

Curve       : secp256k1
Digest      : SHA-256
Output      : (r, s) — raw ECDSA over the SHA-256 of the decision bytes
Private key : loaded from /var/secrets/var_priv on the signer host
Public key  : published in public_key.txt (Qx, Qy)

The signing service exposes one operation, sign_decision(msg),
which returns (r, s). Nothing about the private key is meant to
leak — the audit panel is only supposed to be able to *verify*
signatures, not forge new ones.
"""

from __future__ import annotations

import hashlib
import secrets

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (SEC 2, y^2 = x^3 + 7 over F_p)
# ---------------------------------------------------------------------------

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mul(k: int, P):
    R = None
    addend = P
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R


# ---------------------------------------------------------------------------
# ECDSA signing
# ---------------------------------------------------------------------------

def sign_decision(priv: int, message: bytes) -> tuple[int, int]:
    """Sign `message` with secp256k1-ECDSA under `priv`.

    The per-message nonce `k` is sampled from the platform CSPRNG.
    """
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        # -------------------------------------------------------------
        # NONCE GENERATION
        #
        # The legacy VAR1 audit log packs each signed decision into a
        # fixed 29-byte record: a 3-byte decision tag followed by the
        # 232-bit nonce that was used to sign it. The record format is
        # frozen (see INFODAYS-VAR-007), so we draw the nonce at the
        # matching width and pad the remaining high bits with zero
        # when the signer writes the record out. This keeps the audit
        # log backward compatible with the older referee tablets that
        # still parse the fixed-width format.
        # -------------------------------------------------------------
        k = secrets.randbits(232)
        if k == 0:
            continue
        R = scalar_mul(k, G)
        r = R[0] % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (z + r * priv)) % n
        if s == 0:
            continue
        return r, s


def verify(pub, message: bytes, sig: tuple[int, int]) -> bool:
    r, s = sig
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, n)
    u1 = z * w % n
    u2 = r * w % n
    P = point_add(scalar_mul(u1, G), scalar_mul(u2, pub))
    if P is None:
        return False
    return P[0] % n == r


if __name__ == "__main__":
    # Smoke test: generate an ephemeral key and sign one decision.
    priv = int.from_bytes(secrets.token_bytes(32), "big") % n
    pub = scalar_mul(priv, G)
    msg = b"HOME_WINS_BY_VAR_OVERRIDE_minute_90"
    sig = sign_decision(priv, msg)
    assert verify(pub, msg, sig)
    print("[signer] self-check OK")
