#!/usr/bin/env python3
"""
LM10 reference client — PoW + record/recall/reforge/retire primitives.

Ships alongside the challenge bundle as a protocol helper; the full
exploit lives in solve.py.
"""
import hashlib
import socket
import struct
import sys


MAGIC        = b"LM10"
OP_RECORD    = 0x0A
OP_RECALL    = 0x1E
OP_REFORGE   = 0x4B
OP_RETIRE    = 0x37
OP_CEREMONY  = 0x63
OP_POW_REQ   = 0xEE
OP_POW_REPLY = 0xEF


class LM10Client:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(30)

    def close(self):
        try:
            self.send_frame(bytes([OP_CEREMONY]))
        except Exception:
            pass
        self.sock.close()

    def recv_frame(self):
        hdr = self._read_exact(6)
        if hdr[:4] != MAGIC:
            raise IOError(f"bad magic: {hdr!r}")
        length = struct.unpack(">H", hdr[4:6])[0]
        return self._read_exact(length) if length else b""

    def send_frame(self, body):
        if len(body) > 0xFFFF:
            raise ValueError("body too large")
        self.sock.sendall(MAGIC + struct.pack(">H", len(body)) + body)

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise IOError("short read")
            buf += chunk
        return buf

    # ── Proof-of-work ────────────────────────────────────────────────
    def pass_pow(self):
        body = self.recv_frame()
        if len(body) != 18 or body[0] != OP_POW_REQ:
            raise IOError(f"unexpected PoW frame: {body!r}")
        nonce = body[1:17]
        bits = body[17]
        suffix = mine_pow(nonce, bits)
        self.send_frame(bytes([OP_POW_REPLY]) + suffix)

    # ── Vault ops ────────────────────────────────────────────────────
    def record(self, content):
        body = bytes([OP_RECORD]) + struct.pack(">H", len(content)) + content
        self.send_frame(body)
        resp = self.recv_frame()
        if resp[0] != 0x00:
            raise IOError(f"record failed: {resp!r}")
        return resp[1]

    def recall(self, idx):
        body = bytes([OP_RECALL, idx])
        self.send_frame(body)
        resp = self.recv_frame()
        if resp[0] != 0x00:
            raise IOError(f"recall failed: {resp!r}")
        length = struct.unpack(">H", resp[1:3])[0]
        return resp[3:3 + length]

    def reforge(self, idx, off, newbytes):
        body = (bytes([OP_REFORGE, idx])
                + struct.pack(">HH", off, len(newbytes))
                + newbytes)
        self.send_frame(body)
        resp = self.recv_frame()
        if resp[0] != 0x00:
            raise IOError(f"reforge failed: {resp!r}")

    def retire(self, idx):
        body = bytes([OP_RETIRE, idx])
        self.send_frame(body)
        resp = self.recv_frame()
        if resp[0] != 0x00:
            raise IOError(f"retire failed: {resp!r}")


# ── PoW miner ───────────────────────────────────────────────────────
def mine_pow(nonce, bits):
    required_zero_bytes = bits // 8
    remainder_bits = bits % 8
    mask = (0xFF << (8 - remainder_bits)) & 0xFF if remainder_bits else 0
    counter = 0
    while True:
        suffix = counter.to_bytes(7, "little")
        digest = hashlib.sha256(nonce + suffix).digest()
        if all(b == 0 for b in digest[:required_zero_bytes]) and (
            remainder_bits == 0 or (digest[required_zero_bytes] & mask) == 0
        ):
            return suffix
        counter += 1


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

    client = LM10Client(host, port)
    print("[*] solving PoW ...", file=sys.stderr)
    client.pass_pow()
    print("[+] PoW cleared", file=sys.stderr)

    idx = client.record(b"free kick, top corner")
    print(f"[+] record idx={idx}", file=sys.stderr)
    data = client.recall(idx)
    print(f"[+] recall: {data!r}", file=sys.stderr)

    client.close()


if __name__ == "__main__":
    main()
