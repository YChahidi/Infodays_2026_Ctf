"""
Proof-of-work gate for the batistuta webhook (anti-AI #7).

Stateless scheme — the server holds no nonces:

    sha256(uuid + ':' + bucket + ':' + nonce_hex)

must have >= POW_BITS leading zero bits, where bucket is the current
five-minute UTC epoch index (`int(time.time() // 300)`).

The PoW expectation is re-advertised in the response headers of every
GET /wiki/n8n call so the writeup-following solver knows the rule.
The /webhook/<uuid> POST consumes one nonce per request via
`X-PoW-Nonce: <hex>` — every blind-SQLi probe pays the CPU cost.
"""
import hashlib
import time

POW_BITS = 16
BUCKET_SECONDS = 300


def current_bucket() -> str:
    return str(int(time.time() // BUCKET_SECONDS))


def verify(uuid: str, nonce_hex: str, bucket: str | None = None) -> bool:
    if not nonce_hex:
        return False
    try:
        bytes.fromhex(nonce_hex)
    except ValueError:
        return False
    if bucket is None:
        bucket = current_bucket()
    payload = f"{uuid}:{bucket}:{nonce_hex}".encode()
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


def verify_with_window(uuid: str, nonce_hex: str, grace_buckets: int = 1) -> bool:
    now_bucket = int(time.time() // BUCKET_SECONDS)
    for delta in range(grace_buckets + 1):
        if verify(uuid, nonce_hex, str(now_bucket - delta)):
            return True
    return False
