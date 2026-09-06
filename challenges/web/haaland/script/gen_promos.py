#!/usr/bin/env python3
"""
Generate two promo signatures that reuse the same ECDSA nonce k.

Called from entrypoint.sh before `forge script Deploy.s.sol` is invoked.
Exports the two signatures as env vars PROMO_SIG_1 and PROMO_SIG_2 so the
Deploy script can submit them on-chain via `mintPass`.

Usage (inside the container):
    eval $(python3 script/gen_promos.py)
    forge script ...
"""
from __future__ import annotations

import os
import sys

from eth_hash.auto import keccak
from coincurve import PrivateKey
from coincurve._libsecp256k1 import ffi, lib

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _pass_digest(holder: bytes, nonce: int) -> bytes:
    assert len(holder) == 20
    return keccak(b"HAALAND_GB_PASS_V2" + holder + nonce.to_bytes(32, "big"))


def _sign_with_k(sk_int: int, digest: bytes, k: int) -> tuple[int, int, int]:
    """RFC-free raw ECDSA sign with explicit nonce k."""
    # coincurve wraps libsecp256k1; we call ecdsa_sign with a custom
    # noncefp that always returns our chosen k.
    import ctypes
    from coincurve.context import GLOBAL_CONTEXT

    sig = ffi.new("secp256k1_ecdsa_signature *")

    # Build the extraparams with a constant k
    k_bytes = k.to_bytes(32, "big")

    @ffi.callback("int(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, void *, unsigned int)")
    def noncefp(nonce32, msg32, key32, algo16, data, attempt):
        ffi.memmove(nonce32, k_bytes, 32)
        return 1

    sk_bytes = sk_int.to_bytes(32, "big")
    ok = lib.secp256k1_ecdsa_sign(
        GLOBAL_CONTEXT.ctx, sig, digest, sk_bytes, noncefp, ffi.NULL
    )
    if not ok:
        raise RuntimeError("libsecp256k1 ecdsa_sign failed")

    compact = ffi.new("unsigned char[64]")
    lib.secp256k1_ecdsa_signature_serialize_compact(GLOBAL_CONTEXT.ctx, compact, sig)
    r = int.from_bytes(bytes(compact)[:32], "big")
    s = int.from_bytes(bytes(compact)[32:], "big")

    # Determine v by trying 27 / 28 and seeing which recovers the correct pubkey.
    from eth_keys.main import KeyAPI
    kapi = KeyAPI()
    expected = kapi.PrivateKey(sk_bytes).public_key
    for v_guess in (27, 28):
        try:
            from eth_keys.datatypes import Signature
            sig_obj = Signature(vrs=(v_guess - 27, r, s))
            rec = sig_obj.recover_public_key_from_msg_hash(digest)
            if rec == expected:
                return (r, s, v_guess)
        except Exception:
            continue
    raise RuntimeError("could not determine recovery id v")


def _to_address(sk_bytes: bytes) -> bytes:
    from eth_keys.main import KeyAPI
    return KeyAPI().PrivateKey(sk_bytes).public_key.to_canonical_address()


def main() -> int:
    signer_pk = int(os.environ["SIGNER_PK"], 16)
    promo_pk1 = bytes.fromhex(os.environ["PROMO_PK_1"].removeprefix("0x"))
    promo_pk2 = bytes.fromhex(os.environ["PROMO_PK_2"].removeprefix("0x"))
    # Fixed nonce k (MUST be 1 <= k < n).  Reused across both signatures —
    # that's the intended weakness.
    k = int.from_bytes(keccak(b"HAALAND_DETERMINISTIC_K"), "big") % (SECP256K1_N - 1) + 1

    holder1 = _to_address(promo_pk1)
    holder2 = _to_address(promo_pk2)

    digest1 = _pass_digest(holder1, 0)
    digest2 = _pass_digest(holder2, 0)

    r1, s1, v1 = _sign_with_k(signer_pk, digest1, k)
    r2, s2, v2 = _sign_with_k(signer_pk, digest2, k)

    assert r1 == r2, "k reuse must produce identical r"

    sig1 = r1.to_bytes(32, "big") + s1.to_bytes(32, "big") + bytes([v1])
    sig2 = r2.to_bytes(32, "big") + s2.to_bytes(32, "big") + bytes([v2])

    # Bourne-shell-safe export format
    print(f"export PROMO_SIG_1=0x{sig1.hex()}")
    print(f"export PROMO_SIG_2=0x{sig2.hex()}")
    print(f"export PROMO_HOLDER_1=0x{holder1.hex()}")
    print(f"export PROMO_HOLDER_2=0x{holder2.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
