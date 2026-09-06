#!/usr/bin/env python3
"""
KDB v2 — Pass Signal Protocol solver (INSANE).

Chain:
    1. Pull transcript; there's no anchor, sifting carries ~10% noise,
       transport is AES-GCM.
    2. Build a MaxSAT-style Z3 optimisation:
         - hard constraints: ambiguous frames with exactly one m=1 pin
           individual basis bits (never noisy at that layer — ambiguous
           frames are published without noise in the intended model,
           but just in case they might still be: treat them as hard
           constraints anyway; the protocol's noise model applies to
           every sifting string uniformly).  We toggle these to soft
           with a high weight to be safe.
         - soft constraints (weight 1): one per non-ambiguous frame —
           equality if sift bits = "00", inequality if "11", and
           neither if sift bits are an illegal pattern ("01"/"10",
           which only arises under noise — we skip those).
       Maximise satisfied-soft-constraint count; the solution is the
       most-likely basis under a uniform noise model.
    3. Recover shared_key for both the solved basis AND its global
       complement; pick the one whose SHA-256 prefix matches the
       published `key_fingerprint`.
    4. AES-GCM-encrypt `OPEN THE GATE` under the derived nonce and key,
       send and read the flag.

Usage:
    python3 solve.py [host[:port]]   # default 127.0.0.1:9001
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "handout"))

from protocol import KEY_DERIVATION  # noqa: E402

from Crypto.Cipher import AES
from z3 import Bool, Not, Optimize, sat


def recv_json(sock_file) -> dict:
    line = sock_file.readline()
    if not line:
        raise EOFError("server closed")
    return json.loads(line)


def send_json(sock, obj) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


def recover_basis(transcript: dict) -> list[int]:
    n = transcript["n_basis_slots"]
    bv = [Bool(f"b_{i}") for i in range(n)]
    opt = Optimize()

    frames = transcript["frames"]
    sifts  = transcript["sifting_strings"]
    amb    = transcript["ambiguous_mask"]

    for (a, b, m_a, m_b), sift, is_amb in zip(frames, sifts, amb):
        sb = sift.split(",")[0]
        sX, sZ = int(sb[0]), int(sb[1])
        if not is_amb:
            # non-ambiguous frame: soft constraint, weight 1
            if sX == 0 and sZ == 0:
                opt.add_soft(bv[a] == bv[b], weight=1)
            elif sX == 1 and sZ == 1:
                opt.add_soft(bv[a] != bv[b], weight=1)
            else:
                # "01" / "10" — only noise could produce this; skip
                pass
        else:
            # ambiguous: try to pin individual basis when exactly one m=1
            if m_a == 1 and m_b == 0:
                if sX == 1 and sZ == 0:
                    opt.add_soft(bv[a] == False, weight=1)  # noqa: E712
                elif sX == 0 and sZ == 1:
                    opt.add_soft(bv[a] == True, weight=1)   # noqa: E712
            elif m_a == 0 and m_b == 1:
                if sX == 1 and sZ == 0:
                    opt.add_soft(bv[b] == False, weight=1)  # noqa: E712
                elif sX == 0 and sZ == 1:
                    opt.add_soft(bv[b] == True, weight=1)   # noqa: E712

    if opt.check() != sat:
        raise RuntimeError("Z3 optimise unsat")
    model = opt.model()
    return [int(bool(model[bv[i]])) for i in range(n)]


def derive_key_from_basis(basis: list[int], transcript: dict) -> str:
    """Rebuild the key under the assumption that the transcript's non-
    ambiguous sifting bits were clean; non-matching frames are dropped
    (they're the noisy ones)."""
    out = []
    for (a, b, m_a, m_b), sift, is_amb in zip(
        transcript["frames"], transcript["sifting_strings"], transcript["ambiguous_mask"]
    ):
        if is_amb:
            continue
        orient = ("X" if basis[a] == 0 else "Z") + ("X" if basis[b] == 0 else "Z")
        # The server's `derive_shared_key` uses the CLEAN sifting; for
        # non-ambiguous frames the clean sifting is "00,11" if basis
        # values match, else "11,11".  We rebuild it from basis.
        clean_sb = "00" if basis[a] == basis[b] else "11"
        lookup = f"{clean_sb},11|{orient}"
        out.append(KEY_DERIVATION[lookup])
    return "".join(out)


def solve_shared_key(transcript: dict) -> str:
    basis = recover_basis(transcript)
    flipped = [1 - b for b in basis]
    fp_want = transcript["key_fingerprint"].lower()
    fp_len = len(fp_want)

    for candidate in (basis, flipped):
        key = derive_key_from_basis(candidate, transcript)
        fp = hashlib.sha256(key.encode()).hexdigest()[:fp_len]
        if fp == fp_want:
            return key
    raise RuntimeError("fingerprint mismatch on both flips — noise handling failed")


def derive_nonce(fp_hex: str, counter: int) -> bytes:
    return hashlib.sha256(bytes.fromhex(fp_hex) + counter.to_bytes(4, "big")).digest()[:12]


def encrypt_gcm(shared_key: str, nonce: bytes, plaintext: bytes) -> bytes:
    aes_key = hashlib.sha256(shared_key.encode()).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ct + tag


def solve(host: str, port: int) -> str:
    sock = socket.create_connection((host, port), timeout=30)
    rfile = sock.makefile("r")
    banner = recv_json(rfile)
    print("[*] banner:", json.dumps(banner)[:120])
    transcript = recv_json(rfile)
    print(f"[*] transcript: {len(transcript['frames'])} frames, "
          f"{sum(transcript['ambiguous_mask'])} ambiguous, "
          f"fingerprint={transcript['key_fingerprint']}")

    shared = solve_shared_key(transcript)
    print(f"[*] recovered shared_key ({len(shared)} bits): {shared[:48]}...")

    nonce = derive_nonce(transcript["key_fingerprint"], 0)
    frame = encrypt_gcm(shared, nonce, b"OPEN THE GATE")
    send_json(sock, {"command": frame.hex()})

    resp = recv_json(rfile)
    print("[*] server:", json.dumps(resp)[:200])
    return resp.get("flag", "")


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TARGET", "127.0.0.1:9001")
    host, port = target.rsplit(":", 1)
    # Noise occasionally stranding a connected component on the wrong
    # flip → fingerprint check fails and we burn a session.  Retry.
    for attempt in range(8):
        try:
            flag = solve(host, int(port))
        except Exception as exc:
            print(f"[!] attempt {attempt+1} failed: {exc}")
            continue
        if flag:
            print(f"\nFLAG: {flag}")
            return 0
    print("\n[!] no flag in response after retries", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
