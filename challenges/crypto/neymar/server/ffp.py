"""
FFP1 transport — custom framing + proof-of-work gate.

Every application message is a single FFP1 frame:

    4 bytes  "FFP1"          (magic)
    2 bytes  length (BE)     (payload length, max 65535)
    N bytes  payload          (UTF-8 JSON object)

Before any protocol exchange, the server issues a PoW challenge
(16 random bytes) and requires a nonce such that

    sha256(b"ffp1-pow:" + challenge + nonce)

has at least POW_BITS leading zero bits. This makes every fresh
connection cost real CPU, which is cheap for a human (~0.5s) but
expensive at automation/LLM-agent scale.
"""

import hashlib
import secrets


MAGIC = b"FFP1"
LENGTH_BYTES = 2
MAX_PAYLOAD = (1 << (LENGTH_BYTES * 8)) - 1
POW_BITS_DEFAULT = 18
POW_PREFIX = b"ffp1-pow:"


def leading_zero_bits(buf: bytes) -> int:
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


def read_frame(stream) -> bytes:
    header = stream.read(len(MAGIC) + LENGTH_BYTES)
    if len(header) < len(MAGIC) + LENGTH_BYTES:
        raise EOFError("short header")
    if header[: len(MAGIC)] != MAGIC:
        raise ValueError("bad magic")
    length = int.from_bytes(header[len(MAGIC):], "big")
    payload = b""
    while len(payload) < length:
        chunk = stream.read(length - len(payload))
        if not chunk:
            raise EOFError("short payload")
        payload += chunk
    return payload


def write_frame(stream, payload: bytes) -> None:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    stream.write(MAGIC + len(payload).to_bytes(LENGTH_BYTES, "big") + payload)
    stream.flush()


def new_challenge() -> bytes:
    return secrets.token_bytes(16)


def verify_pow(challenge: bytes, nonce: bytes, bits: int) -> bool:
    if len(nonce) == 0 or len(nonce) > 32:
        return False
    h = hashlib.sha256(POW_PREFIX + challenge + nonce).digest()
    return leading_zero_bits(h) >= bits
