#!/usr/bin/env python3
"""
KDB — Pass Signal Protocol TCP service (v2 / INSANE).

Differences from v1:
    - Transcript includes `key_fingerprint` (16-bit SHA-256 prefix of
      shared_key) and NO basis anchor.  Players must resolve global
      flip ambiguity by fingerprint match.
    - Sifting strings carry ~10% random bit noise, so a naive Z3 solve
      is UNSAT.  A MaxSAT / weighted solve recovers the most-likely
      basis assignment.
    - Commands are AES-GCM (not ECB), nonce tied to protocol hash.
      Any single-bit error in the recovered key fails the auth tag.

Wire format on the command channel:
    client -> server (one JSON line):
        {"command": "<hex>"}  where <hex> = nonce(12) || ct || tag(16)
        nonce = sha256(fingerprint || nonce_counter)[:12]
        nonce_counter starts at 0 and increments per command.

    server responds with {"error": ...} or {"info": ...}.
"""
from __future__ import annotations

import hashlib
import json
import os
import socketserver
import sys
from pathlib import Path

from Crypto.Cipher import AES

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from protocol import generate_session, aes_key_from_shared  # noqa: E402


def _read_flag() -> str:
    for candidate in (HERE / "flag.txt", HERE.parent / "flag.txt"):
        if candidate.exists():
            return candidate.read_text().strip()
    return "INFODAYS{placeholder_flag}"


FLAG = os.environ.get("FLAG") or _read_flag()
MAGIC_COMMAND = b"OPEN THE GATE"


BANNER = (
    "=== Kevin De Bruyne — Pass Signal Protocol (v2) ===\n"
    "Hardened relay: noisy sifting, no anchor, GCM transport.\n"
    "Every misbehaving frame forfeits the session.\n"
)


def _serialize_session(session) -> dict:
    return {
        "info": "public transcript — reconstruct shared_key from this data",
        "n_basis_slots": len(session.basis),
        "frames": [list(f) for f in session.frames],
        "sifting_strings": session.sifting_strings,
        "ambiguous_mask": session.ambiguous_mask,
        "key_fingerprint": session.key_fingerprint,
        "noise_probability": 0.10,
    }


def _derive_nonce(fp_hex: str, counter: int) -> bytes:
    return hashlib.sha256(bytes.fromhex(fp_hex) + counter.to_bytes(4, "big")).digest()[:12]


class Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def _send_json(self, obj):
        line = json.dumps(obj, separators=(",", ":"))
        self.wfile.write((line + "\n").encode())
        self.wfile.flush()

    def handle(self):
        try:
            self._send_json({"info": BANNER})
            session = generate_session()
            aes_key = aes_key_from_shared(session.shared_key)
            self._send_json(_serialize_session(session))

            nonce_counter = 0
            fails_left = 3
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                line = line.decode(errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    raw = bytes.fromhex(msg["command"])
                    nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
                    if len(nonce) != 12 or len(tag) != 16:
                        raise ValueError("bad frame")
                except Exception:
                    self._send_json({"error": "invalid input; expected {'command': 'nonce||ct||tag'}"})
                    continue

                expected_nonce = _derive_nonce(session.key_fingerprint, nonce_counter)
                if nonce != expected_nonce:
                    self._send_json({"error": f"nonce mismatch; expected counter={nonce_counter}"})
                    continue

                try:
                    pt = AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
                except Exception:
                    fails_left -= 1
                    self._send_json({"error": "GCM auth failed", "fails_left": fails_left})
                    if fails_left <= 0:
                        return
                    continue

                nonce_counter += 1
                if pt == MAGIC_COMMAND:
                    self._send_json({
                        "info": "gate unlocked",
                        "coordinates": "51.0543 N, 3.7174 E",
                        "flag": FLAG,
                    })
                    return
                self._send_json({"error": f"unknown command: {pt!r}"})
        except Exception as exc:
            try:
                self._send_json({"error": f"server error: {exc!r}"})
            except Exception:
                pass


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "9001"))
    srv = ThreadedServer((host, port), Handler)
    print(f"[+] KDB v2 listening on {host}:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
