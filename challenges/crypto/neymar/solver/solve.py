#!/usr/bin/env python3
"""
NEYMAR — intended solver for the FFP1 hardened build.

Steps:
  1. Parse FFP1 frames (magic "FFP1" + 2-byte BE length + JSON payload).
  2. Mine an 18-bit PoW nonce over sha256(b"ffp1-pow:" + challenge + nonce).
  3. Read the public handshake (registered_plays, tactics,
     chalkboard_codes, vetoed_tactics).
  4. On every non-vetoed tactic the measured bits are "11" by
     construction, so the first half of each chalkboard_code encodes
     lane-equality: "00" = equal, "11" = distinct. Feed those as 1-bit
     equality / inequality constraints into z3.
  5. Replay BOB_MR_DERIVATION + KEY_DERIVATION to rebuild the match
     cipher (unique up to a global lane flip the derivation table is
     invariant under).
  6. AES-256-ECB encrypt "PASS TO NEYMAR" under sha256(match_cipher),
     send as {"op":"play","cipher_hex":...}, receive flag.
"""
import json
import socket
import sys
import time
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from z3 import BitVec, Solver, sat


MAGIC = b"FFP1"

BOB_MR_DERIVATION = {
    ("X", "X"): 0, ("X", "Z"): 1,
    ("Z", "X"): 1, ("Z", "Z"): 0,
}
KEY_DERIVATION = {
    "00,11": {0: "0", 1: "1"},
    "11,11": {0: "1", 1: "0"},
}


def read_exact(rf, n):
    buf = b""
    while len(buf) < n:
        chunk = rf.read(n - len(buf))
        if not chunk:
            raise EOFError("short read")
        buf += chunk
    return buf


def read_frame(rf):
    header = read_exact(rf, 6)
    if header[:4] != MAGIC:
        raise IOError(f"bad frame header: {header!r}")
    length = int.from_bytes(header[4:6], "big")
    return json.loads(read_exact(rf, length))


def send_frame(wf, obj):
    payload = json.dumps(obj, separators=(",", ":")).encode()
    wf.write(MAGIC + len(payload).to_bytes(2, "big") + payload)
    wf.flush()


def leading_zero_bits(buf):
    bits = 0
    for byte in buf:
        if byte == 0:
            bits += 8
            continue
        for shift in range(7, -1, -1):
            if (byte >> shift) & 1:
                return bits
            bits += 1
        return bits
    return bits


def mine_pow(challenge_hex, bits):
    challenge = bytes.fromhex(challenge_hex)
    t0 = time.time()
    n = 0
    prefix = b"ffp1-pow:" + challenge
    while True:
        nonce = n.to_bytes(8, "little")
        if leading_zero_bits(sha256(prefix + nonce).digest()) >= bits:
            print(f"[+] PoW found in {time.time()-t0:.2f}s (nonce={n})", file=sys.stderr)
            return nonce.hex()
        n += 1


def recover_match_cipher(public):
    frames = [tuple(f) for f in public["tactics"]]
    vetoed = {tuple(f) for f in public["vetoed_tactics"]}
    codes = public["chalkboard_codes"]
    plays = public["registered_plays"]

    lane = [BitVec(f"l{i}", 1) for i in range(max(plays) + 1)]
    solver = Solver()
    used = []
    for frame, code in zip(frames, codes):
        if frame in vetoed:
            continue
        used.append((frame, code))
        sb = code.split(",", 1)[0]
        a, b = frame
        if sb == "00":
            solver.add(lane[a] == lane[b])
        elif sb == "11":
            solver.add(lane[a] != lane[b])
        else:
            raise RuntimeError(f"non-ambig frame with sifting={sb!r}")

    assert solver.check() == sat
    model = solver.model()

    shared = ""
    for (a, b), code in used:
        la = "XZ"[model[lane[a]].as_long()]
        lb = "XZ"[model[lane[b]].as_long()]
        mr = BOB_MR_DERIVATION[(la, lb)]
        shared += KEY_DERIVATION[code][mr]
    return shared


def main(host, port):
    s = socket.create_connection((host, port))
    rf = s.makefile("rb")
    wf = s.makefile("wb")

    msg = read_frame(rf)
    assert msg["op"] == "pow", f"expected pow, got {msg}"
    nonce_hex = mine_pow(msg["challenge"], msg["bits"])
    send_frame(wf, {"op": "pow", "nonce": nonce_hex})

    public = None
    while public is None:
        msg = read_frame(rf)
        op = msg.get("op")
        if op == "handshake":
            public = msg
        elif op == "err":
            print(f"[!] server error: {msg}", file=sys.stderr)
            return
        else:
            print(f"[*] {msg}", file=sys.stderr)

    ready = read_frame(rf)
    assert ready.get("op") == "ready", f"expected ready, got {ready}"

    shared = recover_match_cipher(public)
    key = sha256(shared.encode()).digest()
    ct = AES.new(key, AES.MODE_ECB).encrypt(pad(b"PASS TO NEYMAR", 16))
    send_frame(wf, {"op": "play", "cipher_hex": ct.hex()})

    while True:
        try:
            msg = read_frame(rf)
        except Exception:
            return
        print(json.dumps(msg))
        if msg.get("op") in ("flag", "err"):
            return


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    main(host, port)
