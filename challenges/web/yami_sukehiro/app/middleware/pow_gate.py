"""
Proof-of-work gate for anti-automation.

Scheme (stateless):
    sha256(email + ':' + <bucket> + ':' + nonce_hex)
must have >= POW_BITS leading zero bits, where <bucket> is the current
five-minute UTC epoch bucket (`int(time.time() // 300)`).

    * Client: grind a nonce for ~30ms on a modern CPU.
    * Server: one hash check per request.  No session / DB state.

The five-minute bucket gives solved nonces an at-most-five-minute
shelf life, so harvested nonces can't be replayed long-term.

Anti-AI angle (#7): every /login POST costs the client real CPU work.
AI-driven brute-forcers that don't implement the PoW client get
rejected; ones that do implement it pay 20-30s per 1000 attempts.
"""
import hashlib
import time

POW_BITS = 16
BUCKET_SECONDS = 300  # 5 minutes


def current_bucket() -> str:
    return str(int(time.time() // BUCKET_SECONDS))


def verify(email: str, nonce_hex: str, bucket: str | None = None) -> bool:
    if not nonce_hex:
        return False
    try:
        bytes.fromhex(nonce_hex)
    except ValueError:
        return False
    if bucket is None:
        bucket = current_bucket()
    payload = f"{email}:{bucket}:{nonce_hex}".encode()
    digest = hashlib.sha256(payload).digest()
    need_full = POW_BITS // 8
    need_extra = POW_BITS % 8
    if digest[:need_full] != b'\x00' * need_full:
        return False
    if need_extra:
        mask = (0xff << (8 - need_extra)) & 0xff
        if digest[need_full] & mask:
            return False
    return True


def verify_with_window(email: str, nonce_hex: str, grace_buckets: int = 1) -> bool:
    """Accept the current bucket plus `grace_buckets` previous buckets,
    so clock skew between client and server (up to 5 min per grace) is
    forgiven."""
    now_bucket = int(time.time() // BUCKET_SECONDS)
    for delta in range(grace_buckets + 1):
        if verify(email, nonce_hex, str(now_bucket - delta)):
            return True
    return False
