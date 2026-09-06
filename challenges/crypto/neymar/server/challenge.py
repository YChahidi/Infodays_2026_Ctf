#!/usr/bin/env python3
"""
NEYMAR — PSG "Football Frame Protocol" (FFP1) dispatch channel.

Every connection:
  1. FFP1 framing (magic + length + JSON payload).
  2. 18-bit SHA-256 proof-of-work gate before anything else.
  3. A public/private handshake that negotiates a match_cipher.
  4. An AES-256-ECB command channel keyed by SHA256(match_cipher);
     the command "PASS TO NEYMAR" unlocks the flag.
"""

import json
import os
import sys
from hashlib import sha256
from random import uniform

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from alice import Alice
from bob import Bob
from ffp import POW_BITS_DEFAULT, new_challenge, read_frame, verify_pow, write_frame
from secret import SECRET_MESSAGE


FLAG_PATH = os.environ.get("FLAG_PATH", "/app/flag.txt")
PAIRS = int(os.environ.get("FFP_PAIRS", "1024"))
SECURITY = int(os.environ.get("FFP_SECURITY", "32"))
POW_BITS = int(os.environ.get("FFP_POW_BITS", str(POW_BITS_DEFAULT)))
COMMAND_CODE = "PASS TO NEYMAR"
MAX_COMMANDS = 8

# Wire-visible field names (lexically detached from any textbook QKD term).
FIELD_PLAYS = "registered_plays"
FIELD_TACTICS = "tactics"
FIELD_CODES = "chalkboard_codes"
FIELD_VETO = "vetoed_tactics"


def send(out, obj):
    write_frame(out, json.dumps(obj, separators=(",", ":")).encode())


def recv(inp):
    return json.loads(read_frame(inp))


class FFPSession:
    def __init__(self):
        self._scout = Alice(PAIRS)
        self._dispatcher = Bob(uniform(0, 1))
        self._security = SECURITY
        self.match_cipher = None

    def negotiate(self):
        pairs = self._scout.prepare()
        matchings = self._dispatcher.measure(pairs)
        if not matchings:
            return None

        frames, usable_frames, auxiliary_frames = self._scout.compute_frames(matchings)
        if not frames:
            return None

        codes = self._dispatcher.compute_sifting_strings(frames)
        alice_codes, vetoed = self._scout.error_correction(
            usable_frames, auxiliary_frames, codes
        )
        scout_key = self._scout.generate_shared_key(
            frames, usable_frames, vetoed, alice_codes, codes
        )
        disp_key = self._dispatcher.generate_shared_key(frames, vetoed, codes)
        if len(scout_key) < self._security or scout_key != disp_key:
            return None

        self.match_cipher = scout_key.encode()
        return {
            FIELD_PLAYS: matchings,
            FIELD_TACTICS: [list(f) for f in frames],
            FIELD_CODES: [codes[f] for f in frames],
            FIELD_VETO: [list(f) for f in vetoed],
        }

    def decrypt_play(self, enc_bytes):
        key = sha256(self.match_cipher).digest()
        return unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_bytes), 16).decode()


def pow_gate(inp, out):
    challenge = new_challenge()
    send(out, {
        "op": "pow",
        "challenge": challenge.hex(),
        "bits": POW_BITS,
        "hint": "sha256(b'ffp1-pow:'||challenge||nonce) must have >= bits leading zero bits",
    })
    try:
        reply = recv(inp)
    except Exception:
        return False
    if reply.get("op") != "pow":
        return False
    try:
        nonce = bytes.fromhex(reply.get("nonce", ""))
    except ValueError:
        return False
    return verify_pow(challenge, nonce, POW_BITS)


def run(inp, out):
    if not pow_gate(inp, out):
        send(out, {"op": "err", "msg": "access denied"})
        return

    send(out, {
        "op": "greet",
        "protocol": "FFP1",
        "msg": "PSG scout channel open. Negotiate a match cipher, then relay a play.",
    })

    session = FFPSession()
    for _ in range(64):
        public = session.negotiate()
        if public is not None:
            send(out, {"op": "handshake", **public})
            send(out, {"op": "ready"})
            break
    else:
        send(out, {"op": "err", "msg": "handshake loop exhausted"})
        return

    for _ in range(MAX_COMMANDS):
        try:
            msg = recv(inp)
        except Exception:
            return

        if msg.get("op") != "play":
            send(out, {"op": "err", "msg": "unknown op"})
            continue
        try:
            ct = bytes.fromhex(msg.get("cipher_hex", ""))
            if not ct or len(ct) % 16:
                raise ValueError
        except Exception:
            send(out, {"op": "err", "msg": "bad cipher"})
            continue
        try:
            play = session.decrypt_play(ct)
        except Exception:
            send(out, {"op": "err", "msg": "decrypt failed"})
            continue

        if play == COMMAND_CODE:
            try:
                flag = open(FLAG_PATH).read().strip()
            except Exception:
                flag = "INFODAYS{flag_file_missing}"
            send(out, {"op": "flag", "msg": f"{SECRET_MESSAGE}{flag}"})
            return
        send(out, {"op": "err", "msg": "unknown play"})


def main():
    inp = sys.stdin.buffer
    out = sys.stdout.buffer
    try:
        run(inp, out)
    except Exception as exc:
        try:
            send(out, {"op": "err", "msg": f"internal: {type(exc).__name__}"})
        except Exception:
            pass


if __name__ == "__main__":
    main()
